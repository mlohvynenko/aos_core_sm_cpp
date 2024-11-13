/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <future>

#include <gmock/gmock.h>

#include <aos/test/log.hpp>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/message_differencer.h>
#include <grpcpp/server_builder.h>

#include <servicemanager/v4/servicemanager.grpc.pb.h>

#include "smclient/smclient.hpp"

#include "mocks/certhandlermock.hpp"
#include "mocks/certloadermock.hpp"
#include "mocks/launchermock.hpp"
#include "mocks/logprovidermock.hpp"
#include "mocks/networkmanagermock.hpp"
#include "mocks/nodeinfoprovidermock.hpp"
#include "mocks/provisionmanagermock.hpp"
#include "mocks/resourcemanagermock.hpp"
#include "mocks/resourcemonitormock.hpp"
#include "mocks/x509providermock.hpp"

using namespace testing;
using namespace aos;

/***********************************************************************************************************************
 * Test utils
 **********************************************************************************************************************/

namespace common::v1 {

bool operator==(const ErrorInfo& lhs, const ErrorInfo& rhs)
{
    return google::protobuf::util::MessageDifferencer::Equals(lhs, rhs);
}

} // namespace common::v1

namespace servicemanager::v4 {
bool operator==(const SMProto::NodeConfigStatus& lhs, const SMProto::NodeConfigStatus& rhs)
{
    return google::protobuf::util::MessageDifferencer::Equals(lhs, rhs);
}

} // namespace servicemanager::v4

static aos::NodeInfo CreateNodeInfo()
{
    aos::NodeInfo result;

    result.mNodeID = "test-node-id";

    return result;
}

static aos::monitoring::NodeMonitoringData CreateNodeMonitoringData()
{
    aos::monitoring::NodeMonitoringData monitoringData;

    monitoringData.mNodeID                   = "test-node-id";
    monitoringData.mMonitoringData.mCPU      = 1;
    monitoringData.mMonitoringData.mRAM      = 2;
    monitoringData.mMonitoringData.mDownload = 3;
    monitoringData.mMonitoringData.mUpload   = 4;

    return monitoringData;
}

static aos::alerts::AlertVariant CreateAlert()
{
    aos::alerts::AlertVariant result;

    aos::alerts::SystemAlert systemAlert;

    systemAlert.mMessage   = "test-message";
    systemAlert.mTimestamp = aos::Time::Now();

    result.SetValue<aos::alerts::SystemAlert>(systemAlert);

    return result;
}

static aos::PushLog CreatePushLog()
{
    aos::PushLog log;

    log.mContent    = "test log";
    log.mLogID      = "test-log-id";
    log.mPart       = 0;
    log.mPartsCount = 1;

    return log;
}

static aos::InstanceStatusStaticArray CreateInstanceStatus()
{
    aos::InstanceStatusStaticArray instances;

    aos::InstanceStatus instance;
    instance.mInstanceIdent  = aos::InstanceIdent {"service-id", "instance-id", 0};
    instance.mRunState       = aos::InstanceRunStateEnum::eActive;
    instance.mServiceVersion = "1.0.0";

    instances.PushBack(instance);

    return instances;
}

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

class TestSMService : public SMProto::SMService::Service {
public:
    TestSMService(const std::string& url) { mServer = CreateServer(url, grpc::InsecureServerCredentials()); }

    ~TestSMService()
    {
        if (mCtx) {
            mCtx->TryCancel();
        }
    }

    grpc::Status RegisterSM(grpc::ServerContext*                                            context,
        grpc::ServerReaderWriter<SMProto::SMIncomingMessages, SMProto::SMOutgoingMessages>* stream) override
    {
        LOG_INF() << "Test server message thread started";

        try {

            mStream = stream;
            mCtx    = context;

            SMProto::SMOutgoingMessages incomingMsg;

            while (stream->Read(&incomingMsg)) {
                {
                    if (std::string msgStr; google::protobuf::TextFormat::PrintToString(incomingMsg, &msgStr)) {
                        LOG_DBG() << "Received message: " << msgStr.c_str();
                    } else {
                        LOG_ERR() << "Can't convert message to string";
                    }

                    if (incomingMsg.has_node_config_status()) {
                        OnNodeConfigStatus(incomingMsg.node_config_status());

                        mNodeConfigStatusCV.notify_all();
                        continue;
                    } else if (incomingMsg.has_run_instances_status()) {
                        OnRunInstancesStatus(incomingMsg.run_instances_status());
                    } else if (incomingMsg.has_update_instances_status()) {
                        OnUpdateInstancesStatus(incomingMsg.update_instances_status());
                    } else if (incomingMsg.has_override_env_var_status()) {
                        OnOverrideEnvVarStatus(incomingMsg.override_env_var_status());
                    } else if (incomingMsg.has_log()) {
                        OnLogData(incomingMsg.log());
                    } else if (incomingMsg.has_instant_monitoring()) {
                        OnInstantMonitoring(incomingMsg.instant_monitoring());
                    } else if (incomingMsg.has_average_monitoring()) {
                        OnAverageMonitoring(incomingMsg.average_monitoring());
                    } else if (incomingMsg.has_alert()) {
                        OnAlert(incomingMsg.alert());
                    } else if (incomingMsg.has_image_content_request()) {
                        OnImageContentRequest(incomingMsg.image_content_request());
                    } else if (incomingMsg.has_clock_sync_request()) {
                        OnClockSyncRequest(incomingMsg.clock_sync_request());
                    } else {
                        LOG_ERR() << "Unknown message received in test server";

                        continue;
                    }

                    mResponseCV.notify_all();
                }
            }
        } catch (const std::exception& e) {
            LOG_ERR() << e.what();
        }

        LOG_DBG() << "Test server message thread stoped";

        mStream = nullptr;
        mCtx    = nullptr;

        return grpc::Status::OK;
    }

    MOCK_METHOD(void, OnNodeConfigStatus, (const SMProto::NodeConfigStatus&));
    MOCK_METHOD(void, OnRunInstancesStatus, (const SMProto::RunInstancesStatus&));
    MOCK_METHOD(void, OnUpdateInstancesStatus, (const SMProto::UpdateInstancesStatus&));
    MOCK_METHOD(void, OnOverrideEnvVarStatus, (const SMProto::OverrideEnvVarStatus&));
    MOCK_METHOD(void, OnLogData, (const SMProto::LogData&));
    MOCK_METHOD(void, OnInstantMonitoring, (const SMProto::InstantMonitoring&));
    MOCK_METHOD(void, OnAverageMonitoring, (const SMProto::AverageMonitoring&));
    MOCK_METHOD(void, OnAlert, (const SMProto::Alert&));
    MOCK_METHOD(void, OnImageContentRequest, (const SMProto::ImageContentRequest&));
    MOCK_METHOD(void, OnClockSyncRequest, (const SMProto::ClockSyncRequest&));

    void GetNodeConfigStatus()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_get_node_config_status();

        mStream->Write(incomingMsg);
    }

    void CheckNodeConfig(const std::string& version, const std::string& config)
    {
        SMProto::SMIncomingMessages incomingMsg;

        auto checkNodeConfig = incomingMsg.mutable_check_node_config();

        checkNodeConfig->set_version(version);
        checkNodeConfig->set_node_config(config);

        mStream->Write(incomingMsg);
    }

    void SetNodeConfig(const std::string& version, const std::string& config)
    {
        SMProto::SMIncomingMessages incomingMsg;

        auto setNodeConfig = incomingMsg.mutable_set_node_config();

        setNodeConfig->set_version(version);
        setNodeConfig->set_node_config(config);

        mStream->Write(incomingMsg);
    }

    void RunInstances()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_run_instances();

        mStream->Write(incomingMsg);
    }

    void UpdateNetwork()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_update_networks();

        mStream->Write(incomingMsg);
    }

    void GetSystemLog()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_system_log_request();

        mStream->Write(incomingMsg);
    }

    void GetInstanceLog()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_instance_log_request();

        mStream->Write(incomingMsg);
    }

    void GetInstanceCrashLog()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_instance_crash_log_request();

        mStream->Write(incomingMsg);
    }

    void OverrideEnvVars()
    {
        SMProto::SMIncomingMessages incomingMsg;

        incomingMsg.mutable_override_env_vars();

        mStream->Write(incomingMsg);
    }

    void WaitNodeConfigStatus(const std::chrono::seconds& timeout = std::chrono::seconds(4))
    {
        std::unique_lock lock {mLock};

        mNodeConfigStatusCV.wait_for(lock, timeout);
    }

    void WaitMessage(const std::chrono::seconds& timeout = std::chrono::seconds(4))
    {
        std::unique_lock lock {mLock};

        mResponseCV.wait_for(lock, timeout);
    }

    aos::Error SendMessage(const SMProto::SMIncomingMessages& msg)
    {
        if (!mStream) {
            return aos::Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "stream is not initialized");
        }

        if (!mStream->Write(msg)) {
            return aos::Error(AOS_ERROR_WRAP(ErrorEnum::eFailed), "can't send message");
        }

        return aos::ErrorEnum::eNone;
    }

private:
    std::unique_ptr<grpc::Server> CreateServer(
        const std::string& addr, const std::shared_ptr<grpc::ServerCredentials>& credentials)
    {
        grpc::ServerBuilder builder;

        builder.AddListeningPort(addr, credentials);
        builder.RegisterService(static_cast<SMProto::SMService::Service*>(this));

        return builder.BuildAndStart();
    }

    grpc::ServerReaderWriter<SMProto::SMIncomingMessages, SMProto::SMOutgoingMessages>* mStream = nullptr;
    grpc::ServerContext*                                                                mCtx    = nullptr;

    std::mutex              mLock;
    std::condition_variable mNodeConfigStatusCV;
    std::condition_variable mResponseCV;

    std::unique_ptr<grpc::Server> mServer;
};

class SMClientTest : public Test {
protected:
    void SetUp() override { InitLog(); }

    static aos::sm::config::Config GetConfig()
    {
        sm::config::Config config;

        config.mCMServerURL = "localhost:5555";
        config.mCertStorage = "sm";
        config.mCACert      = "";

        return config;
    }

    std::unique_ptr<sm::client::SMClient> CreateClient(
        bool provisionMode, const sm::config::Config& config = GetConfig())
    {
        auto client = std::make_unique<sm::client::SMClient>();

        auto err = client->Init(config, mProvisionManager, mCertLoader, mCryptoProvider, mNodeInfoProvider,
            mResourceManager, mNetworkManager, mLogProvider, mResourceMonitor, mLauncher, provisionMode);

        if (!err.IsNone()) {
            LOG_ERR() << "Can't init client: error=" << err.Message();

            return nullptr;
        }

        return client;
    }

    std::unique_ptr<TestSMService> CreateServer(const std::string& url) { return std::make_unique<TestSMService>(url); }

    std::pair<std::unique_ptr<TestSMService>, std::unique_ptr<sm::client::SMClient>> InitTest(
        const sm::config::Config& config = GetConfig(), bool provisionMode = true)
    {
        auto server = CreateServer(config.mCMServerURL);

        auto client = CreateClient(true, config);

        NodeInfo                                nodeInfo          = CreateNodeInfo();
        RetWithError<StaticString<cVersionLen>> nodeConfigVersion = {"1.0.0", ErrorEnum::eNone};
        SMProto::NodeConfigStatus               expNodeConfigVersion;

        expNodeConfigVersion.set_node_id(nodeInfo.mNodeID.CStr());
        expNodeConfigVersion.set_node_type(nodeInfo.mNodeType.CStr());
        expNodeConfigVersion.set_version(nodeConfigVersion.mValue.CStr());

        EXPECT_CALL(mNodeInfoProvider, GetNodeInfo)
            .WillRepeatedly(DoAll(SetArgReferee<0>(nodeInfo), Return(ErrorEnum::eNone)));
        EXPECT_CALL(mResourceManager, GetNodeConfigVersion).WillRepeatedly(Return(nodeConfigVersion));

        EXPECT_CALL(*server, OnNodeConfigStatus(expNodeConfigVersion)).Times(1);

        if (!provisionMode) {
            EXPECT_CALL(mProvisionManager, SubscribeCertChanged).WillOnce(Return(ErrorEnum::eNone));
            EXPECT_CALL(mProvisionManager, UnsubscribeCertChanged).WillOnce(Return(ErrorEnum::eNone));
        }

        if (auto err = client->Start(); !err.IsNone()) {
            LOG_ERR() << "Can't start client: error=" << err.Message();

            return std::make_pair(nullptr, nullptr);
        }

        server->WaitNodeConfigStatus();

        return std::make_pair(std::move(server), std::move(client));
    }

    iam::provisionmanager::ProvisionManagerMock mProvisionManager;
    CertLoaderItfMock                           mCertLoader;
    ProviderItfMock                             mCryptoProvider;
    NodeInfoProviderMock                        mNodeInfoProvider;
    ResourceManagerMock                         mResourceManager;
    NetworkManagerMock                          mNetworkManager;
    LogProviderMock                             mLogProvider;
    ResourceMonitorMock                         mResourceMonitor;
    LauncherMock                                mLauncher;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(SMClientTest, ClientNotStarted)
{
    auto server = CreateServer(GetConfig().mCMServerURL);
    ASSERT_NE(server, nullptr) << "Can't create server";

    auto client = CreateClient(true);
    ASSERT_NE(client, nullptr) << "Can't create client";

    EXPECT_CALL(*server, OnNodeConfigStatus).Times(0);
    server->WaitNodeConfigStatus();

    auto err = client->Stop();
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << "Stop should return failed if start wasn't called" << err.Message();
}

TEST_F(SMClientTest, SecondStartReturnsError)
{
    auto [server, client] = InitTest();

    auto err = client->Start();
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed))
        << "Start should return failed if client isn't closed" << err.Message();

    err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, StartFailsOnGetNodeInfoError)
{
    auto server = CreateServer(GetConfig().mCMServerURL);
    ASSERT_NE(server, nullptr) << "Can't create server";

    auto client = CreateClient(true);
    ASSERT_NE(client, nullptr) << "Can't create client";

    EXPECT_CALL(mNodeInfoProvider, GetNodeInfo).WillOnce(Return(aos::ErrorEnum::eFailed));

    auto err = client->Start();
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed))
        << "Start should return failed if get node info fails: error=" << err.Message();
}

TEST_F(SMClientTest, MonitoringDataIsSent)
{
    auto [server, client] = InitTest();

    auto monitoringData = CreateNodeMonitoringData();

    EXPECT_CALL(*server, OnInstantMonitoring).Times(1);

    auto err = client->SendMonitoringData(monitoringData);
    EXPECT_TRUE(err.IsNone()) << "Can't send monitoring data: error=" << err.Message();

    server->WaitMessage();

    err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, AlertIsSent)
{
    auto [server, client] = InitTest();

    auto alerts = CreateAlert();

    EXPECT_CALL(*server, OnAlert).Times(1);

    auto err = client->SendAlert(alerts);
    EXPECT_TRUE(err.IsNone()) << "Can't send alerts: error=" << err.Message();

    server->WaitMessage();

    err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, LogDataIsSent)
{
    auto [server, client] = InitTest();

    auto log = CreatePushLog();

    EXPECT_CALL(*server, OnLogData).Times(1);

    auto err = client->OnLogReceived(log);
    EXPECT_TRUE(err.IsNone()) << "Can't send log data: error=" << err.Message();

    server->WaitMessage();

    err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, InstancesRunStatusIsSent)
{
    auto [server, client] = InitTest();

    auto instanceStatus = CreateInstanceStatus();

    EXPECT_CALL(*server, OnRunInstancesStatus).Times(1);

    auto err = client->InstancesRunStatus(instanceStatus);
    EXPECT_TRUE(err.IsNone()) << "Can't send instance run status: error=" << err.Message();

    server->WaitMessage();

    err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, InstancesUpdateStatusIsSent)
{
    auto [server, client] = InitTest();

    auto instanceStatus = CreateInstanceStatus();

    auto err = client->InstancesUpdateStatus(instanceStatus);
    EXPECT_TRUE(err.IsNone()) << "Can't send instance update status: error=" << err.Message();

    server->WaitMessage(std::chrono::seconds(1));

    err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, GetNodeConfigStatusIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnNodeConfigStatus).Times(1);

    server->GetNodeConfigStatus();

    server->WaitNodeConfigStatus();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, CheckNodeConfigIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnNodeConfigStatus).Times(1);
    EXPECT_CALL(mResourceManager, CheckNodeConfig).WillOnce(Return(ErrorEnum::eNone));

    server->CheckNodeConfig("1.0.1", "{}");

    server->WaitNodeConfigStatus();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, SetNodeConfigIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnNodeConfigStatus).Times(1);
    EXPECT_CALL(mResourceManager, UpdateNodeConfig).WillOnce(Return(ErrorEnum::eNone));

    server->SetNodeConfig("1.0.1", "{}");

    server->WaitNodeConfigStatus();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, RunInstancesIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnRunInstancesStatus).Times(1);
    EXPECT_CALL(mLauncher, RunInstances).WillOnce(Invoke([&] {
        client->InstancesRunStatus(CreateInstanceStatus());

        return ErrorEnum::eNone;
    }));

    server->RunInstances();

    server->WaitMessage();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, UpdateNetworkIsHandled)
{
    auto [server, client] = InitTest();

    std::promise<void> promise;

    EXPECT_CALL(mNetworkManager, UpdateNetworks).WillOnce(Invoke([&] {
        promise.set_value();

        return ErrorEnum::eNone;
    }));

    server->UpdateNetwork();

    auto status = promise.get_future().wait_for(std::chrono::seconds(1));
    EXPECT_EQ(status, std::future_status::ready) << "network manager wasn't called";

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, GetSystemLogIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnLogData).Times(1);
    EXPECT_CALL(mLogProvider, GetSystemLog).WillOnce(Invoke([&] {
        client->OnLogReceived(CreatePushLog());

        return ErrorEnum::eNone;
    }));

    server->GetSystemLog();

    server->WaitMessage();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, GetInstanceLogIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnLogData).Times(1);
    EXPECT_CALL(mLogProvider, GetInstanceLog).WillOnce(Invoke([&] {
        client->OnLogReceived(CreatePushLog());

        return ErrorEnum::eNone;
    }));

    server->GetInstanceLog();

    server->WaitMessage();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, GetInstanceCrashLogIsHandled)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnLogData).Times(1);
    EXPECT_CALL(mLogProvider, GetInstanceCrashLog).WillOnce(Invoke([&] {
        client->OnLogReceived(CreatePushLog());

        return ErrorEnum::eNone;
    }));

    server->GetInstanceCrashLog();

    server->WaitMessage();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, OverrideEnvVarsSucceeds)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnOverrideEnvVarStatus).Times(1);
    EXPECT_CALL(mLauncher, OverrideEnvVars).WillOnce(Return(aos::ErrorEnum::eNone));

    server->OverrideEnvVars();

    server->WaitMessage();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}

TEST_F(SMClientTest, OverrideEnvVarsFails)
{
    auto [server, client] = InitTest();

    EXPECT_CALL(*server, OnOverrideEnvVarStatus).Times(1);
    EXPECT_CALL(mLauncher, OverrideEnvVars).WillOnce(Return(aos::ErrorEnum::eFailed));

    server->OverrideEnvVars();

    server->WaitMessage();

    auto err = client->Stop();
    ASSERT_TRUE(err.IsNone()) << "Can't stop client: error=" << err.Message();
}
