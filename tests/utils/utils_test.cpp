/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include <aos/test/log.hpp>

#include "utils/convert.hpp"

using namespace testing;
using namespace aos;

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

class UtilsTest : public Test {
public:
    void SetUp() override { aos::InitLog(); }
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(UtilsTest, ConvertAosErrorToProto)
{
    aos::Error params[] = {
        aos::Error {aos::ErrorEnum::eFailed, "failed error"},
        aos::Error {aos::ErrorEnum::eRuntime, "runtime error"},
        aos::Error {aos::ErrorEnum::eNone},
    };

    size_t iteration = 0;

    for (const auto& err : params) {
        LOG_INF() << "Test iteration: " << iteration++;

        auto result = aos::sm::utils::ConvertAosErrorToProto(err);

        EXPECT_EQ(result.aos_code(), static_cast<int32_t>(err.Value()));
        EXPECT_EQ(result.exit_code(), err.Errno());
        EXPECT_EQ(aos::String(result.message().c_str()), err.Message()) << err.Message();
    }
}

TEST_F(UtilsTest, ConvertInstanceIdentToProto)
{
    aos::InstanceIdent          param {"service-id", "subject-id", 1};
    ::common::v1::InstanceIdent result;

    aos::sm::utils::ConvertToProto(param, result);

    EXPECT_EQ(result.service_id(), param.mServiceID.CStr());
    EXPECT_EQ(result.subject_id(), param.mSubjectID.CStr());
    EXPECT_EQ(result.instance(), param.mInstance);
}

TEST_F(UtilsTest, ConvertPushLogToProto)
{
    aos::PushLog                  param;
    ::servicemanager::v4::LogData result;

    param.mLogID      = "log-id";
    param.mPartsCount = 2;
    param.mPart       = 2;
    param.mContent    = "content";
    param.mStatus     = "status";
    param.mErrorInfo  = aos::ErrorEnum::eNone;

    aos::sm::utils::ConvertToProto(param, result);

    EXPECT_EQ(aos::String(result.log_id().c_str()), param.mLogID);
    EXPECT_EQ(result.part_count(), param.mPartsCount);
    EXPECT_EQ(result.part(), param.mPart);
    EXPECT_EQ(aos::String(result.data().c_str()), param.mContent);
    EXPECT_EQ(aos::String(result.status().c_str()), param.mStatus);
    EXPECT_FALSE(result.has_error());
}

static aos::PartitionInfo CreatePartition(const aos::String& name, size_t usedSize)
{
    aos::PartitionInfo result;

    result.mName     = name;
    result.mUsedSize = usedSize;

    return result;
}

TEST_F(UtilsTest, ConvertMonitoringDataToProto)
{
    aos::monitoring::MonitoringData      param;
    aos::Time                            timestamp = aos::Time::Now();
    ::servicemanager::v4::MonitoringData result;

    param.mRAM      = 1;
    param.mCPU      = 2;
    param.mDownload = 3;
    param.mUpload   = 4;

    param.mPartitions.PushBack(CreatePartition("partition1", 10));

    aos::sm::utils::ConvertToProto(param, timestamp, result);

    EXPECT_EQ(result.ram(), param.mRAM);
    EXPECT_EQ(result.cpu(), param.mCPU);
    EXPECT_EQ(result.download(), param.mDownload);
    EXPECT_EQ(result.upload(), param.mUpload);

    EXPECT_EQ(result.timestamp().seconds(), timestamp.UnixTime().tv_sec);

    ASSERT_EQ(result.partitions_size(), param.mPartitions.Size());

    for (size_t i = 0; i < param.mPartitions.Size(); ++i) {
        const auto& partition   = param.mPartitions[i];
        const auto& pbPartition = result.partitions(i);

        EXPECT_EQ(pbPartition.name(), partition.mName.CStr());
        EXPECT_EQ(pbPartition.used_size(), partition.mUsedSize);
    }
}

TEST_F(UtilsTest, ConvertNodeMonitoringDataToProto)
{
    aos::monitoring::NodeMonitoringData     param;
    ::servicemanager::v4::AverageMonitoring result;

    param.mTimestamp = aos::Time::Now();

    aos::InstanceIdent              instanceIdent {"service-id", "subject-id", 1};
    aos::monitoring::MonitoringData monitoringData;

    monitoringData.mCPU = 1000;

    param.mServiceInstances.PushBack({instanceIdent, monitoringData});
    param.mMonitoringData.mCPU = 2000;

    aos::sm::utils::ConvertToProto(param, result);

    EXPECT_EQ(result.node_monitoring().cpu(), param.mMonitoringData.mCPU);
    EXPECT_EQ(result.node_monitoring().timestamp().seconds(), param.mTimestamp.UnixTime().tv_sec);
    EXPECT_EQ(result.node_monitoring().timestamp().nanos(), param.mTimestamp.UnixTime().tv_nsec);

    ASSERT_EQ(result.instances_monitoring_size(), param.mServiceInstances.Size());
    for (size_t i = 0; i < param.mServiceInstances.Size(); ++i) {
        const auto& instanceMonitoring   = param.mServiceInstances[i];
        const auto& pbInstanceMonitoring = result.instances_monitoring(i);

        EXPECT_EQ(aos::String(pbInstanceMonitoring.instance().service_id().c_str()), instanceIdent.mServiceID);
        EXPECT_EQ(aos::String(pbInstanceMonitoring.instance().subject_id().c_str()), instanceIdent.mSubjectID);
        EXPECT_EQ(pbInstanceMonitoring.instance().instance(), instanceIdent.mInstance);

        EXPECT_EQ(pbInstanceMonitoring.monitoring_data().timestamp().seconds(), param.mTimestamp.UnixTime().tv_sec);
        EXPECT_EQ(pbInstanceMonitoring.monitoring_data().timestamp().nanos(), param.mTimestamp.UnixTime().tv_nsec);
        EXPECT_EQ(pbInstanceMonitoring.monitoring_data().cpu(), instanceMonitoring.mMonitoringData.mCPU);
    }
}

TEST_F(UtilsTest, ConvertInstanceStatusToProto)
{
    aos::InstanceStatus                  param;
    ::servicemanager::v4::InstanceStatus result;

    param.mInstanceIdent  = aos::InstanceIdent {"service-id", "subject-id", 1};
    param.mServiceVersion = "1.0.0";
    param.mRunState       = aos::InstanceRunStateEnum::eActive;

    aos::sm::utils::ConvertToProto(param, result);

    EXPECT_EQ(aos::String(result.instance().service_id().c_str()), param.mInstanceIdent.mServiceID);
    EXPECT_EQ(aos::String(result.instance().subject_id().c_str()), param.mInstanceIdent.mSubjectID);
    EXPECT_EQ(result.instance().instance(), param.mInstanceIdent.mInstance);

    EXPECT_EQ(aos::String(result.service_version().c_str()), param.mServiceVersion);
    EXPECT_EQ(aos::String(result.run_state().c_str()), param.mRunState.ToString());
}

TEST_F(UtilsTest, ConvertInstanceFilterToProto)
{
    aos::Optional<aos::StaticString<aos::cServiceIDLen>> serviceIDNullopt {};
    aos::Optional<aos::StaticString<aos::cSubjectIDLen>> subjectIDNullopt {};
    aos::Optional<uint64_t>                              instanceNullopt {};

    aos::InstanceFilter params[] = {
        aos::InstanceFilter {serviceIDNullopt, subjectIDNullopt, instanceNullopt},
        aos::InstanceFilter {serviceIDNullopt, {"subject-id"}, {1}},
        aos::InstanceFilter {{"service-id"}, subjectIDNullopt, {1}},
        aos::InstanceFilter {{"service-id"}, {"subject-id"}, instanceNullopt},
        aos::InstanceFilter {{"service-id"}, {"subject-id"}, {1}},
    };

    size_t iteration = 0;

    for (const auto& param : params) {
        LOG_INF() << "Test iteration: " << iteration++;

        ::servicemanager::v4::InstanceFilter result;

        aos::sm::utils::ConvertToProto(param, result);

        if (param.mServiceID.HasValue()) {
            EXPECT_EQ(result.service_id(), param.mServiceID.GetValue().CStr());
        } else {
            EXPECT_TRUE(result.service_id().empty());
        }

        if (param.mSubjectID.HasValue()) {
            EXPECT_EQ(result.subject_id(), param.mSubjectID.GetValue().CStr());
        } else {
            EXPECT_TRUE(result.subject_id().empty());
        }

        if (param.mInstance.HasValue()) {
            EXPECT_EQ(result.instance(), param.mInstance.GetValue());
        } else {
            EXPECT_EQ(result.instance(), -1);
        }
    }
}

TEST_F(UtilsTest, ConvertEnvVarStatusToProto)
{
    aos::EnvVarStatus params[] = {
        {"name1", aos::Error {aos::ErrorEnum::eFailed, "failed error"}},
        {"name2", aos::Error {aos::ErrorEnum::eRuntime, "runtime error"}},
        {"name3", aos::Error {aos::ErrorEnum::eNone}},
    };

    size_t iteration = 0;

    for (const auto& param : params) {
        LOG_INF() << "Test iteration: " << iteration++;

        ::servicemanager::v4::EnvVarStatus result;

        aos::sm::utils::ConvertToProto(param, result);

        EXPECT_EQ(aos::String(result.name().c_str()), param.mName);

        if (param.mError.IsNone()) {
            EXPECT_FALSE(result.has_error());
        } else {
            EXPECT_TRUE(result.has_error());

            EXPECT_EQ(result.error().aos_code(), static_cast<int32_t>(param.mError.Value()));
            EXPECT_EQ(result.error().exit_code(), param.mError.Errno());
            EXPECT_EQ(aos::String(result.error().message().c_str()), param.mError.Message());
        }
    }
}

TEST_F(UtilsTest, ConvertInstanceIdentToAos)
{
    ::common::v1::InstanceIdent param;

    param.set_service_id("service-id");
    param.set_subject_id("subject-id");
    param.set_instance(1);

    auto result = aos::sm::utils::ConvertToAos(param);

    EXPECT_EQ(result.mServiceID, aos::String(param.service_id().c_str()));
    EXPECT_EQ(result.mSubjectID, aos::String(param.subject_id().c_str()));
    EXPECT_EQ(result.mInstance, param.instance());
}

TEST_F(UtilsTest, ConvertNetworkParametersToAos)
{
    ::servicemanager::v4::NetworkParameters param;

    param.set_network_id("network-id");
    param.set_subnet("subnet");
    param.set_ip("ip");
    param.set_vlan_id(1);

    for (const auto& dns : {"dns1", "dns2"}) {
        param.add_dns_servers(dns);
    }

    for (const auto& ruleSfx : {"1", "2"}) {
        auto& rule = *param.add_rules();

        rule.set_dst_ip(std::string("dst-ip").append(ruleSfx));
        rule.set_dst_port(std::string("40").append(ruleSfx));
        rule.set_proto(std::string("proto").append(ruleSfx));
        rule.set_src_ip(std::string("src-ip").append(ruleSfx));
    }

    auto result = aos::sm::utils::ConvertToAos(param);

    EXPECT_EQ(result.mNetworkID, aos::String(param.network_id().c_str()));
    EXPECT_EQ(result.mSubnet, aos::String(param.subnet().c_str()));
    EXPECT_EQ(result.mIP, aos::String(param.ip().c_str()));
    EXPECT_EQ(result.mVlanID, param.vlan_id());

    ASSERT_EQ(result.mDNSServers.Size(), param.dns_servers_size());
    for (size_t i = 0; i < result.mDNSServers.Size(); ++i) {
        EXPECT_EQ(result.mDNSServers[i], aos::String(param.dns_servers(i).c_str()));
    }

    ASSERT_EQ(result.mFirewallRules.Size(), param.rules_size());
    for (size_t i = 0; i < result.mFirewallRules.Size(); ++i) {
        const auto& rule   = result.mFirewallRules[i];
        const auto& pbRule = param.rules(i);

        EXPECT_EQ(rule.mDstIP, aos::String(pbRule.dst_ip().c_str()));
        EXPECT_EQ(rule.mDstPort, aos::String(pbRule.dst_port().c_str()));
        EXPECT_EQ(rule.mProto, aos::String(pbRule.proto().c_str()));
        EXPECT_EQ(rule.mSrcIP, aos::String(pbRule.src_ip().c_str()));
    }
}

TEST_F(UtilsTest, ConvertInstanceInfoToAos)
{
    ::servicemanager::v4::InstanceInfo param;

    param.mutable_instance()->set_service_id("service-id");
    param.mutable_instance()->set_subject_id("subject-id");
    param.mutable_instance()->set_instance(1);

    param.set_uid(10);
    param.set_storage_path("storage-path");
    param.set_state_path("state-path");

    param.mutable_network_parameters()->set_network_id("network-id");

    auto result = aos::sm::utils::ConvertToAos(param);

    EXPECT_EQ(result.mInstanceIdent.mServiceID, aos::String(param.instance().service_id().c_str()));
    EXPECT_EQ(result.mInstanceIdent.mSubjectID, aos::String(param.instance().subject_id().c_str()));
    EXPECT_EQ(result.mInstanceIdent.mInstance, param.instance().instance());

    EXPECT_EQ(result.mUID, param.uid());
    EXPECT_EQ(result.mStoragePath, aos::String(param.storage_path().c_str()));
    EXPECT_EQ(result.mStatePath, aos::String(param.state_path().c_str()));

    EXPECT_EQ(result.mNetworkParameters.mNetworkID, aos::String(param.network_parameters().network_id().c_str()));
}

TEST_F(UtilsTest, ConvertInstanceFilterToAos)
{
    struct {
        std::string serviceID;
        std::string subjectID;
        int64_t     instance;
    } params[] = {
        {"service-id", "subject-id", 1},
        {"service-id", "subject-id", -1},
        {"service-id", "", 1},
        {"", "subject-id", 1},
        {"", "", -1},
    };

    size_t iteration = 0;

    for (const auto& param : params) {
        LOG_INF() << "Test iteration: " << iteration++;

        ::servicemanager::v4::InstanceFilter pbParam;

        pbParam.set_service_id(param.serviceID);
        pbParam.set_subject_id(param.subjectID);
        pbParam.set_instance(param.instance);

        auto result = aos::sm::utils::ConvertToAos(pbParam);

        if (!param.serviceID.empty()) {
            EXPECT_EQ(result.mServiceID.GetValue(), aos::String(param.serviceID.c_str()));
        } else {
            EXPECT_FALSE(result.mServiceID.HasValue());
        }

        if (!param.subjectID.empty()) {
            EXPECT_EQ(result.mSubjectID.GetValue(), aos::String(param.subjectID.c_str()));
        } else {
            EXPECT_FALSE(result.mSubjectID.HasValue());
        }

        if (param.instance != -1) {
            EXPECT_EQ(result.mInstance.GetValue(), param.instance);
        } else {
            EXPECT_FALSE(result.mInstance.HasValue());
        }
    }
}

TEST_F(UtilsTest, ConvertEnvVarInfoToAos)
{
    ::servicemanager::v4::EnvVarInfo param;

    param.set_name("name");
    param.set_value("value");
    param.mutable_ttl()->set_seconds(1);

    auto result = aos::sm::utils::ConvertToAos(param);

    EXPECT_EQ(result.mName, aos::String(param.name().c_str()));
    EXPECT_EQ(result.mValue, aos::String(param.value().c_str()));
    EXPECT_EQ(result.mTTL, aos::Time::Unix(1, 0));
}

TEST_F(UtilsTest, ConvertTimestampToAos)
{
    aos::Optional<aos::Time> expected {aos::Time::Now()};

    google::protobuf::Timestamp param;
    param.set_seconds(expected.GetValue().UnixTime().tv_sec);
    param.set_nanos(expected.GetValue().UnixTime().tv_nsec);

    auto result = aos::sm::utils::ConvertToAos(param);
    EXPECT_EQ(result, expected);

    param.Clear();
    expected.Reset();

    result = aos::sm::utils::ConvertToAos(param);
    EXPECT_EQ(result, expected);
}

TEST_F(UtilsTest, ConvertServiceInfoToAos)
{
    ::servicemanager::v4::ServiceInfo param;

    param.set_service_id("service-id");
    param.set_provider_id("provider-id");
    param.set_version("1.0.0");
    param.set_gid(10);
    param.set_url("url");
    param.set_sha256("sha256");
    param.set_size(100);

    auto result = aos::sm::utils::ConvertToAos(param);

    EXPECT_EQ(result.mServiceID, aos::String(param.service_id().c_str()));
    EXPECT_EQ(result.mProviderID, aos::String(param.provider_id().c_str()));
    EXPECT_EQ(result.mVersion, aos::String(param.version().c_str()));
    EXPECT_EQ(result.mGID, param.gid());
    EXPECT_EQ(result.mURL, aos::String(param.url().c_str()));
    EXPECT_EQ(result.mSHA256, aos::String(param.sha256().c_str()));
    EXPECT_EQ(result.mSize, param.size());
}

TEST_F(UtilsTest, ConvertLayerInfoToAos)
{
    ::servicemanager::v4::LayerInfo param;

    param.set_layer_id("layer-id");
    param.set_digest("digest");
    param.set_version("1.0.0");
    param.set_url("url");
    param.set_sha256("sha256");
    param.set_size(100);

    auto result = aos::sm::utils::ConvertToAos(param);

    EXPECT_EQ(result.mLayerID, aos::String(param.layer_id().c_str()));
    EXPECT_EQ(result.mLayerDigest, aos::String(param.digest().c_str()));
    EXPECT_EQ(result.mVersion, aos::String(param.version().c_str()));
    EXPECT_EQ(result.mURL, aos::String(param.url().c_str()));
    EXPECT_EQ(result.mSHA256, aos::String(param.sha256().c_str()));
    EXPECT_EQ(result.mSize, param.size());
}

TEST_F(UtilsTest, ConvertSystemAlertToProto)
{
    aos::alerts::AlertVariant param;

    aos::alerts::SystemAlert systemAlert;
    systemAlert.mTimestamp = aos::Time::Now();
    systemAlert.mMessage   = "message";

    param.SetValue<aos::alerts::SystemAlert>(systemAlert);

    ::servicemanager::v4::Alert result;

    aos::sm::utils::ConvertToProto(param, result);

    ASSERT_TRUE(result.has_system_alert());

    EXPECT_EQ(result.timestamp().seconds(), systemAlert.mTimestamp.UnixTime().tv_sec);
    EXPECT_EQ(result.timestamp().nanos(), systemAlert.mTimestamp.UnixTime().tv_nsec);

    const auto& pbSystemAlert = result.system_alert();
    EXPECT_EQ(aos::String(pbSystemAlert.message().c_str()), systemAlert.mMessage);
}
