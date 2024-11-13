/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SMCLIENT_HPP_
#define SMCLIENT_HPP_

#include <condition_variable>
#include <thread>

#include <grpcpp/channel.h>
#include <grpcpp/security/credentials.h>

#include <aos/common/alerts/alertsender.hpp>
#include <aos/common/crypto.hpp>
#include <aos/common/cryptoutils.hpp>
#include <aos/common/monitoring/monitoring.hpp>
#include <aos/common/tools/error.hpp>
#include <aos/iam/certhandler.hpp>
#include <aos/iam/nodeinfoprovider.hpp>
#include <aos/iam/provisionmanager.hpp>
#include <aos/sm/launcher.hpp>
#include <aos/sm/logprovider.hpp>
#include <aos/sm/networkmanager.hpp>
#include <aos/sm/resourcemanager.hpp>

#include <servicemanager/v4/servicemanager.grpc.pb.h>

#include "config/config.hpp"

namespace SMProto = servicemanager::v4;

namespace aos::sm::client {

using PublicNodeService = SMProto::SMService;

/**
 * GRPC service manager client.
 */
class SMClient : private iam::certhandler::CertReceiverItf,
                 //  private iam::nodeinfoprovider::NodeStatusObserverItf,
                 public alerts::AlertSenderItf,
                 private sm::launcher::InstanceStatusReceiverItf,
                 public monitoring::SenderItf,
                 public sm::logprovider::LogsObserverItf,
                 private NonCopyable {
public:
    /**
     * Initializes IAM client instance.
     *
     * @param config client configuration.
     * @param provisionManager provision manager.
     * @param certLoader certificate loader.
     * @param cryptoProvider crypto provider.
     * @param nodeInfoProvider node info provider.
     * @param resourceManager resource manager.
     * @param networkManager network manager.
     * @param logProvider log provider.
     * @param resourceMonitor resource monitor.
     * @param launcher launcher.
     * @param provisioningMode flag indicating whether provisioning mode is active.
     * @returns Error.
     */
    Error Init(const config::Config& config, iam::provisionmanager::ProvisionManagerItf& provisionManager,
        cryptoutils::CertLoaderItf& certLoader, crypto::x509::ProviderItf& cryptoProvider,
        iam::nodeinfoprovider::NodeInfoProviderItf& nodeInfoProvider,
        sm::resourcemanager::ResourceManagerItf& resourceManager, sm::networkmanager::NetworkManagerItf& networkManager,
        sm::logprovider::LogProviderItf& logProvider, monitoring::ResourceMonitorItf& resourceMonitor,
        sm::launcher::LauncherItf& launcher, bool provisioningMode);

    /**
     * Starts the client.
     *
     * @return Error.
     */
    Error Start();

    /**
     * Stops the client.
     *
     * @return Error.
     */
    Error Stop();

    /**
     * Sends monitoring data.
     *
     * @param monitoringData monitoring data.
     * @return Error.
     */
    Error SendMonitoringData(const monitoring::NodeMonitoringData& monitoringData) override;

    /**
     * Sends alert data.
     *
     * @param alert alert variant.
     * @return Error.
     */
    Error SendAlert(const alerts::AlertVariant& alert) override;

    /**
     * On log received event handler.
     *
     * @param log log.
     * @return Error.
     */
    Error OnLogReceived(const PushLog& log) override;

    /**
     * Sends instances run status.
     *
     * @param instances instances status array.
     * @return Error.
     */
    Error InstancesRunStatus(const Array<InstanceStatus>& instances) override;

    /**
     * Sends instances update status.
     * @param instances instances status array.
     *
     * @return Error.
     */
    Error InstancesUpdateStatus(const Array<InstanceStatus>& instances) override;

    /**
     * Destroys object instance.
     */
    ~SMClient() = default;

private:
    void OnCertChanged(const iam::certhandler::CertInfo& info) override;

    using StubPtr = std::unique_ptr<SMProto::SMService::StubInterface>;
    using StreamPtr
        = std::unique_ptr<grpc::ClientReaderWriterInterface<SMProto::SMOutgoingMessages, SMProto::SMIncomingMessages>>;

    std::unique_ptr<grpc::ClientContext> CreateClientContext();
    StubPtr CreateStub(const std::string& url, const std::shared_ptr<grpc::ChannelCredentials>& credentials);

    bool RegisterSM(const std::string& url);

    void ConnectionLoop() noexcept;
    void HandleIncomingMessages() noexcept;

    bool SendNodeConfigStatus(const String& version, const Error& configErr);

    bool ProcessGetNodeConfigStatus();
    bool ProcessCheckNodeConfig(const SMProto::CheckNodeConfig& request);
    bool ProcessSetNodeConfig(const SMProto::SetNodeConfig& request);
    bool ProcessRunInstances(const SMProto::RunInstances& request);
    bool ProcessUpdateNetworks(const SMProto::UpdateNetworks& request);
    bool ProcessGetSystemLogRequest(const SMProto::SystemLogRequest& request);
    bool ProcessGetInstanceLogRequest(const SMProto::InstanceLogRequest& request);
    bool ProcessGetInstanceCrashLogRequest(const SMProto::InstanceCrashLogRequest& request);
    bool ProcessOverrideEnvVars(const SMProto::OverrideEnvVars& request);
    bool ProcessGetAverageMonitoring();
    bool ProcessConnectionStatus(const SMProto::ConnectionStatus& request);

    config::Config                              mConfig;
    iam::provisionmanager::ProvisionManagerItf* mProvisionManager = nullptr;
    cryptoutils::CertLoaderItf*                 mCertLoader       = nullptr;
    crypto::x509::ProviderItf*                  mCryptoProvider   = nullptr;
    iam::nodeinfoprovider::NodeInfoProviderItf* mNodeInfoProvider = nullptr;
    sm::resourcemanager::ResourceManagerItf*    mResourceManager  = nullptr;
    sm::networkmanager::NetworkManagerItf*      mNetworkManager   = nullptr;
    sm::logprovider::LogProviderItf*            mLogProvider      = nullptr;
    monitoring::ResourceMonitorItf*             mResourceMonitor  = nullptr;
    sm::launcher::LauncherItf*                  mLauncher         = nullptr;

    std::vector<std::shared_ptr<grpc::ChannelCredentials>> mCredentialList;
    bool                                                   mCredentialListUpdated = false;

    common::utils::Duration mReconnectInterval;
    bool                    mProvisioningMode = false;

    NodeInfo                             mNodeInfo;
    std::unique_ptr<grpc::ClientContext> mCtx;
    StreamPtr                            mStream;
    StubPtr                              mStub;

    std::atomic_bool        mStopped = true;
    std::thread             mConnectionThread;
    std::condition_variable mStoppedCV;
    std::mutex              mMutex;
};

} // namespace aos::sm::client

#endif
