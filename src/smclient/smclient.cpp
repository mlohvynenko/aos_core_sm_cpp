/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Poco/Pipe.h>
#include <Poco/PipeStream.h>
#include <Poco/Process.h>
#include <Poco/StreamCopier.h>

#include <utils/exception.hpp>
#include <utils/grpchelper.hpp>

#include "logger/logmodule.hpp"
#include "smclient.hpp"
#include "utils/convert.hpp"

namespace aos::sm::client {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error SMClient::Init(const config::Config& config, iam::provisionmanager::ProvisionManagerItf& provisionManager,
    cryptoutils::CertLoaderItf& certLoader, crypto::x509::ProviderItf& cryptoProvider,
    iam::nodeinfoprovider::NodeInfoProviderItf& nodeInfoProvider,
    sm::resourcemanager::ResourceManagerItf& resourceManager, sm::networkmanager::NetworkManagerItf& networkManager,
    sm::logprovider::LogProviderItf& logProvider, monitoring::ResourceMonitorItf& resourceMonitor,
    sm::launcher::LauncherItf& launcher, bool provisioningMode)
{
    LOG_DBG() << "Init SMClient";

    mConfig           = config;
    mNodeInfoProvider = &nodeInfoProvider;
    mCertLoader       = &certLoader;
    mCryptoProvider   = &cryptoProvider;
    mProvisionManager = &provisionManager;
    mResourceManager  = &resourceManager;
    mNetworkManager   = &networkManager;
    mLogProvider      = &logProvider;
    mResourceMonitor  = &resourceMonitor;
    mLauncher         = &launcher;
    mProvisioningMode = provisioningMode;

    return ErrorEnum::eNone;
}

Error SMClient::Start()
{
    LOG_DBG() << "Start SMClient";

    std::lock_guard lock {mMutex};

    auto err = mNodeInfoProvider->GetNodeInfo(mNodeInfo);
    if (!err.IsNone()) {
        LOG_ERR() << "Can't get node info: error=" << err.Message();

        return Error(AOS_ERROR_WRAP(err), "can't get node info");
    }

    if (mStopped.exchange(false) == false) {
        return Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "client already started");
    }

    if (mProvisioningMode) {
        mCredentialList.push_back(grpc::InsecureChannelCredentials());
        if (!mConfig.mCACert.empty()) {
            mCredentialList.push_back(common::utils::GetTLSClientCredentials(mConfig.mCACert.c_str()));
        }

    } else {
        iam::certhandler::CertInfo certInfo;

        err = mProvisionManager->GetCert(String(mConfig.mCertStorage.c_str()), {}, {}, certInfo);
        if (!err.IsNone()) {
            LOG_ERR() << "Get certificates failed: error=" << err.Message();

            return AOS_ERROR_WRAP(ErrorEnum::eInvalidArgument);
        }

        err = mProvisionManager->SubscribeCertChanged(String(mConfig.mCertStorage.c_str()), *this);
        if (!err.IsNone()) {
            LOG_ERR() << "Subscribe certificate receiver failed: error=" << err.Message();

            return AOS_ERROR_WRAP(ErrorEnum::eInvalidArgument);
        }

        mCredentialList.push_back(
            common::utils::GetMTLSClientCredentials(certInfo, mConfig.mCACert.c_str(), *mCertLoader, *mCryptoProvider));
    }

    mConnectionThread = std::thread(&SMClient::ConnectionLoop, this);

    return ErrorEnum::eNone;
}

Error SMClient::Stop()
{
    LOG_DBG() << "Stop SMClient";

    if (mStopped.exchange(true) == true) {
        return Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "client stopped");
    }

    mStoppedCV.notify_all();

    {
        std::unique_lock lock {mMutex};

        if (!mProvisioningMode) {
            mProvisionManager->UnsubscribeCertChanged(*this);
        }

        if (mCtx) {
            mCtx->TryCancel();
        }

        mCredentialList.clear();
    }

    if (mConnectionThread.joinable()) {
        mConnectionThread.join();
    }

    return ErrorEnum::eNone;
}

Error SMClient::SendMonitoringData(const monitoring::NodeMonitoringData& monitoringData)
{
    LOG_DBG() << "Send monitoring data";

    SMProto::SMOutgoingMessages outgoingMessage;
    auto&                       response = *outgoingMessage.mutable_instant_monitoring();

    utils::ConvertToProto(monitoringData, response);

    if (!mStream->Write(outgoingMessage)) {
        LOG_ERR() << "Can't send monitoring data";

        return Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "can't send monitoring data");
    }

    return ErrorEnum::eNone;
}

Error SMClient::SendAlert(const alerts::AlertVariant& alert)
{
    (void)alert;

    LOG_DBG() << "Send alert";

    SMProto::SMOutgoingMessages outgoingMessage;

    utils::ConvertToProto(alert, *outgoingMessage.mutable_alert());

    if (!mStream->Write(outgoingMessage)) {
        LOG_ERR() << "Can't send alerts";

        return Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "can't send alerts");
    }

    return ErrorEnum::eNone;
}

Error SMClient::OnLogReceived(const PushLog& log)
{
    LOG_DBG() << "On log received";

    SMProto::SMOutgoingMessages outgoingMessage;

    utils::ConvertToProto(log, *outgoingMessage.mutable_log());

    if (!mStream->Write(outgoingMessage)) {
        LOG_ERR() << "Can't send log";

        return Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "can't send log");
    }

    return ErrorEnum::eNone;
}

Error SMClient::InstancesRunStatus(const Array<InstanceStatus>& instances)
{
    std::lock_guard lock {mMutex};

    LOG_INF() << "Send run instances status";

    SMProto::SMOutgoingMessages outgoingMessage;
    auto&                       response = *outgoingMessage.mutable_run_instances_status();

    for (const auto& instance : instances) {
        utils::ConvertToProto(instance, *response.add_instances());
    }

    return mStream->Write(outgoingMessage) ? ErrorEnum::eNone : ErrorEnum::eFailed;
}

Error SMClient::InstancesUpdateStatus(const Array<InstanceStatus>& instances)
{
    std::lock_guard lock {mMutex};

    LOG_INF() << "Send update instances status";

    SMProto::SMOutgoingMessages outgoingMessage;
    auto&                       response = *outgoingMessage.mutable_update_instances_status();

    for (const auto& instance : instances) {
        utils::ConvertToProto(instance, *response.add_instances());
    }

    return mStream->Write(outgoingMessage) ? ErrorEnum::eNone : ErrorEnum::eFailed;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

void SMClient::OnCertChanged(const iam::certhandler::CertInfo& info)
{
    std::unique_lock lock {mMutex};

    LOG_DBG() << "Certificate changed";

    mCredentialList.clear();
    mCredentialList.push_back(
        common::utils::GetMTLSClientCredentials(info, mConfig.mCACert.c_str(), *mCertLoader, *mCryptoProvider));

    mCredentialListUpdated = true;
}

std::unique_ptr<grpc::ClientContext> SMClient::CreateClientContext()
{
    return std::make_unique<grpc::ClientContext>();
}

SMClient::StubPtr SMClient::CreateStub(
    const std::string& url, const std::shared_ptr<grpc::ChannelCredentials>& credentials)
{
    auto channel = grpc::CreateCustomChannel(url, credentials, grpc::ChannelArguments());
    if (!channel) {
        LOG_ERR() << "Can't create client channel";

        return nullptr;
    }

    return SMProto::SMService::NewStub(channel);
}

bool SMClient::RegisterSM(const std::string& url)
{
    std::unique_lock lock {mMutex};

    for (const auto& credentials : mCredentialList) {
        if (mStopped) {
            return false;
        }

        mStub = CreateStub(url, credentials);
        if (!mStub) {
            LOG_ERR() << "Stub is not created";

            continue;
        }

        mCtx    = CreateClientContext();
        mStream = mStub->RegisterSM(mCtx.get());
        if (!mStream) {
            LOG_ERR() << "Stream creation problem";

            continue;
        }

        auto [version, configErr] = mResourceManager->GetNodeConfigVersion();

        if (!SendNodeConfigStatus(version, configErr)) {
            LOG_WRN() << "Connection failed with provided credentials";

            continue;
        }

        LOG_DBG() << "Connection established";

        mCredentialListUpdated = false;

        return true;
    }

    return false;
}

void SMClient::ConnectionLoop() noexcept
{
    LOG_DBG() << "SMClient connection thread started";

    while (true) {
        LOG_DBG() << "Connecting to SM Server...";

        if (RegisterSM(mConfig.mCMServerURL)) {
            HandleIncomingMessages();

            LOG_DBG() << "SMClient connection closed";
        }

        std::unique_lock lock {mMutex};

        mStoppedCV.wait_for(lock, mReconnectInterval, [this]() { return mStopped == true; });
        if (mStopped) {
            break;
        }
    }

    LOG_DBG() << "SMClient connection thread stopped";
}

void SMClient::HandleIncomingMessages() noexcept
{
    try {
        SMProto::SMIncomingMessages incomingMsg;

        while (mStream->Read(&incomingMsg)) {
            bool ok = true;

            if (incomingMsg.has_get_node_config_status()) {
                ok = ProcessGetNodeConfigStatus();
            } else if (incomingMsg.has_check_node_config()) {
                ok = ProcessCheckNodeConfig(incomingMsg.check_node_config());
            } else if (incomingMsg.has_set_node_config()) {
                ok = ProcessSetNodeConfig(incomingMsg.set_node_config());
            } else if (incomingMsg.has_run_instances()) {
                ok = ProcessRunInstances(incomingMsg.run_instances());
            } else if (incomingMsg.has_update_networks()) {
                ok = ProcessUpdateNetworks(incomingMsg.update_networks());
            } else if (incomingMsg.has_system_log_request()) {
                ok = ProcessGetSystemLogRequest(incomingMsg.system_log_request());
            } else if (incomingMsg.has_instance_log_request()) {
                ok = ProcessGetInstanceLogRequest(incomingMsg.instance_log_request());
            } else if (incomingMsg.has_instance_crash_log_request()) {
                ok = ProcessGetInstanceCrashLogRequest(incomingMsg.instance_crash_log_request());
            } else if (incomingMsg.has_override_env_vars()) {
                ok = ProcessOverrideEnvVars(incomingMsg.override_env_vars());
            } else if (incomingMsg.has_get_average_monitoring()) {
                ok = ProcessGetAverageMonitoring();
            } else if (incomingMsg.has_connection_status()) {
                ok = ProcessConnectionStatus(incomingMsg.connection_status());
            } else {
                AOS_ERROR_CHECK_AND_THROW("Not supported request type", ErrorEnum::eNotSupported);
            }

            if (!ok) {
                break;
            }

            {
                std::unique_lock lock {mMutex};

                if (mCredentialListUpdated) {
                    LOG_DBG() << "Credential list updated: closing connection";

                    mCtx->TryCancel();

                    break;
                }
            }
        }

    } catch (const std::exception& e) {
        LOG_ERR() << e.what();
    }
}

bool SMClient::SendNodeConfigStatus(const String& version, const Error& configErr)
{
    LOG_DBG() << "Send node config status";

    SMProto::SMOutgoingMessages outgoingMsg;
    auto&                       nodeConfigStatus = *outgoingMsg.mutable_node_config_status();

    utils::SetErrorInfo(configErr, nodeConfigStatus);

    nodeConfigStatus.set_version(version.CStr());
    nodeConfigStatus.set_node_id(mNodeInfo.mNodeID.CStr());
    nodeConfigStatus.set_node_type(mNodeInfo.mNodeType.CStr());

    return mStream->Write(outgoingMsg);
}

bool SMClient::ProcessGetNodeConfigStatus()
{
    LOG_INF() << "Process get node config status";

    auto [version, configErr] = mResourceManager->GetNodeConfigVersion();

    return SendNodeConfigStatus(version, configErr);
}

bool SMClient::ProcessCheckNodeConfig(const SMProto::CheckNodeConfig& request)
{
    auto version    = String(request.version().c_str());
    auto nodeConfig = String(request.node_config().c_str());

    LOG_INF() << "Process check node config: version=" << version;

    auto configErr = mResourceManager->CheckNodeConfig(version, nodeConfig);

    return SendNodeConfigStatus(version, configErr);
}

bool SMClient::ProcessSetNodeConfig(const SMProto::SetNodeConfig& request)
{
    auto version    = String(request.version().c_str());
    auto nodeConfig = String(request.node_config().c_str());

    LOG_INF() << "Process set node config: version=" << version;

    auto configErr = mResourceManager->UpdateNodeConfig(version, nodeConfig);

    return SendNodeConfigStatus(version, configErr);
}

bool SMClient::ProcessRunInstances(const SMProto::RunInstances& request)
{
    LOG_INF() << "Process run instances";

    ServiceInfoStaticArray aosServices;
    for (const auto& service : request.services()) {
        if (auto err = aosServices.PushBack(utils::ConvertToAos(service)); !err.IsNone()) {
            LOG_ERR() << "Failed on push back service info: err=" << err;

            return false;
        }
    }

    LayerInfoStaticArray aosLayers;
    for (const auto& layer : request.layers()) {
        if (auto err = aosLayers.PushBack(utils::ConvertToAos(layer)); !err.IsNone()) {
            LOG_ERR() << "Failed on push back layer info: err=" << err;

            return false;
        }
    }

    InstanceInfoStaticArray aosInstances;
    for (const auto& instance : request.instances()) {
        if (auto err = aosInstances.PushBack(utils::ConvertToAos(instance)); !err.IsNone()) {
            LOG_ERR() << "Failed on push back instance info: err=" << err;

            return false;
        }
    }

    auto err = mLauncher->RunInstances(aosServices, aosLayers, aosInstances, request.force_restart());
    if (!err.IsNone()) {
        LOG_ERR() << "Run instances failed: err=" << err;

        return false;
    }

    return true;
}

bool SMClient::ProcessUpdateNetworks(const SMProto::UpdateNetworks& request)
{
    (void)request;

    StaticArray<NetworkParameters, cMaxNumNetworks> networkParams;

    for (const auto& network : request.networks()) {
        if (auto err = networkParams.PushBack(utils::ConvertToAos(network)); !err.IsNone()) {
            LOG_ERR() << "Failed on push back network parameters: err=" << err;

            return false;
        }
    }

    if (auto err = mNetworkManager->UpdateNetworks(networkParams); !err.IsNone()) {
        LOG_ERR() << "Can't update networks: err=" << err;

        return false;
    }

    return true;
}

bool SMClient::ProcessGetSystemLogRequest(const SMProto::SystemLogRequest& request)
{
    LOG_DBG() << "Process get system log request: logID=" << request.log_id().c_str();

    RequestLog logRequest;

    logRequest.mLogID        = String(request.log_id().c_str());
    logRequest.mFilter.mFrom = utils::ConvertToAos(request.from());
    logRequest.mFilter.mTill = utils::ConvertToAos(request.till());

    if (auto err = mLogProvider->GetSystemLog(logRequest); !err.IsNone()) {
        LOG_ERR() << "Get system log failed: err=" << err;

        return false;
    }

    return true;
}

bool SMClient::ProcessGetInstanceLogRequest(const SMProto::InstanceLogRequest& request)
{
    LOG_DBG() << "Process get instance log request: logID=" << request.log_id().c_str();

    RequestLog logRequest;

    logRequest.mLogID                  = String(request.log_id().c_str());
    logRequest.mFilter.mFrom           = utils::ConvertToAos(request.from());
    logRequest.mFilter.mTill           = utils::ConvertToAos(request.till());
    logRequest.mFilter.mInstanceFilter = utils::ConvertToAos(request.instance_filter());

    if (auto err = mLogProvider->GetInstanceLog(logRequest); !err.IsNone()) {
        LOG_ERR() << "Get instance log failed: err=" << err;

        return false;
    }

    return true;
}

bool SMClient::ProcessGetInstanceCrashLogRequest(const SMProto::InstanceCrashLogRequest& request)
{
    LOG_DBG() << "Process get instance crash log request: logID=" << request.log_id().c_str();

    RequestLog logRequest;

    logRequest.mLogID                  = String(request.log_id().c_str());
    logRequest.mFilter.mFrom           = utils::ConvertToAos(request.from());
    logRequest.mFilter.mTill           = utils::ConvertToAos(request.till());
    logRequest.mFilter.mInstanceFilter = utils::ConvertToAos(request.instance_filter());

    if (auto err = mLogProvider->GetInstanceCrashLog(logRequest); !err.IsNone()) {
        LOG_ERR() << "Get instance crash log failed: err=" << err;

        return false;
    }

    return true;
}

bool SMClient::ProcessOverrideEnvVars(const SMProto::OverrideEnvVars& request)
{
    LOG_DBG() << "Process override env vars";

    EnvVarsInstanceInfoArray envVarsInstanceInfos;

    for (const auto& envVar : request.env_vars()) {
        auto instanceFilter = utils::ConvertToAos(envVar.instance_filter());

        EnvVarInfoArray variables;
        for (const auto& var : envVar.variables()) {
            if (auto err = variables.PushBack(utils::ConvertToAos(var)); !err.IsNone()) {
                LOG_ERR() << "Failed on push back env var info: err=" << err;

                return false;
            }
        }
    }

    EnvVarsInstanceStatusArray envVarStatuses;

    auto err = mLauncher->OverrideEnvVars(envVarsInstanceInfos, envVarStatuses);

    SMProto::SMOutgoingMessages outgoingMsg;
    auto&                       response = *outgoingMsg.mutable_override_env_var_status();

    if (!err.IsNone()) {
        utils::SetErrorInfo(err, response);

        return mStream->Write(outgoingMsg);
    }

    for (const auto& status : envVarStatuses) {
        auto& envVarStatus = *response.add_env_vars_status();

        utils::ConvertToProto(status.mFilter, *envVarStatus.mutable_instance_filter());

        for (const auto& env : status.mStatuses) {
            utils::ConvertToProto(env, *envVarStatus.add_statuses());
        }
    }

    if (!mStream->Write(outgoingMsg)) {
        LOG_ERR() << "Can't send override env vars status: err=" << err;

        return false;
    }

    return true;
}

bool SMClient::ProcessGetAverageMonitoring()
{
    LOG_INF() << "Process get average monitoring";

    SMProto::SMOutgoingMessages outgoingMsg;
    auto&                       response = *outgoingMsg.mutable_average_monitoring();

    monitoring::NodeMonitoringData monitoringData;

    if (auto err = mResourceMonitor->GetAverageMonitoringData(monitoringData); !err.IsNone()) {
        LOG_ERR() << "Get average monitoring data failed: err=" << err;

        return false;
    }

    utils::ConvertToProto(monitoringData, response);

    return mStream->Write(outgoingMsg);
}

bool SMClient::ProcessConnectionStatus(const SMProto::ConnectionStatus& request)
{
    LOG_DBG() << "Process connection status: cloudStatus=" << request.cloud_status();

    if (auto err = mLauncher->SetCloudConnection(request.cloud_status()); !err.IsNone()) {
        LOG_ERR() << "Set cloud connection failed: err=" << err;

        return false;
    }

    return true;
}

} // namespace aos::sm::client
