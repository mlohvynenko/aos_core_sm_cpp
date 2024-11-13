/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "convert.hpp"

namespace aos::sm::utils {

const aos::Array<uint8_t> ConvertByteArrayToAos(const std::string& arr)
{
    return {reinterpret_cast<const uint8_t*>(arr.c_str()), arr.length()};
}

static google::protobuf::Timestamp TimestampToPB(const aos::Time& time)
{
    auto unixTime = time.UnixTime();

    google::protobuf::Timestamp result;

    result.set_seconds(unixTime.tv_sec);
    result.set_nanos(static_cast<int32_t>(unixTime.tv_nsec));

    return result;
}

common::v1::ErrorInfo ConvertAosErrorToProto(const aos::Error& error)
{
    common::v1::ErrorInfo result;

    result.set_aos_code(static_cast<int32_t>(error.Value()));
    result.set_exit_code(error.Errno());

    if (!error.IsNone()) {
        aos::StaticString<aos::cErrorMessageLen> message;

        auto err = message.Convert(error);

        result.set_message(err.IsNone() ? message.CStr() : error.Message());
    }

    return result;
}

void ConvertToProto(const aos::InstanceIdent& src, common::v1::InstanceIdent& dst)
{
    dst.set_service_id(src.mServiceID.CStr());
    dst.set_subject_id(src.mSubjectID.CStr());
    dst.set_instance(src.mInstance);
}

void ConvertToProto(const aos::PushLog& src, ::servicemanager::v4::LogData& dst)
{
    dst.set_log_id(src.mLogID.CStr());
    dst.set_part_count(src.mPartsCount);
    dst.set_part(src.mPart);
    dst.set_data(src.mContent.CStr());
    dst.set_status(src.mStatus.CStr());

    SetErrorInfo(src.mErrorInfo, dst);
}

void ConvertToProto(
    const aos::monitoring::MonitoringData& src, const aos::Time& timestamp, servicemanager::v4::MonitoringData& dst)
{
    dst.set_ram(src.mRAM);
    dst.set_cpu(static_cast<uint64_t>(src.mCPU));
    dst.set_download(src.mDownload);
    dst.set_upload(src.mUpload);
    dst.mutable_timestamp()->CopyFrom(TimestampToPB(timestamp));

    for (const auto& partition : src.mPartitions) {
        auto& pbPartition = *dst.add_partitions();

        pbPartition.set_name(partition.mName.CStr());
        pbPartition.set_used_size(partition.mUsedSize);
    }
}

void ConvertToProto(const aos::InstanceStatus& src, servicemanager::v4::InstanceStatus& dst)
{
    ConvertToProto(src.mInstanceIdent, *dst.mutable_instance());

    dst.set_service_version(src.mServiceVersion.CStr());
    dst.set_run_state(src.mRunState.ToString().CStr());

    dst.clear_error_info();
}

void ConvertToProto(const aos::InstanceFilter& src, servicemanager::v4::InstanceFilter& dst)
{
    if (src.mServiceID.HasValue()) {
        dst.set_service_id(src.mServiceID.GetValue().CStr());
    }

    if (src.mSubjectID.HasValue()) {
        dst.set_subject_id(src.mSubjectID.GetValue().CStr());
    }

    dst.set_instance(-1);
    if (src.mInstance.HasValue()) {
        dst.set_instance(static_cast<int64_t>(src.mInstance.GetValue()));
    }
}

void ConvertToProto(const aos::EnvVarStatus& src, servicemanager::v4::EnvVarStatus& dst)
{
    dst.set_name(src.mName.CStr());

    if (!src.mError.IsNone()) {
        utils::SetErrorInfo(src.mError, dst);
    }
}

::servicemanager::v4::Alert CreateAlert(const aos::alerts::AlertItem& src)
{
    ::servicemanager::v4::Alert pbAlert;

    pbAlert.set_tag(src.mTag.CStr());
    *pbAlert.mutable_timestamp() = TimestampToPB(src.mTimestamp);

    return pbAlert;
}

struct AlertVisitor : aos::StaticVisitor<::servicemanager::v4::Alert> {
    Res Visit(const aos::alerts::SystemAlert& val) const
    {
        Res   result  = CreateAlert(val);
        auto& pbAlert = *result.mutable_system_alert();

        pbAlert.set_message(val.mMessage.CStr());

        return result;
    }

    Res Visit(const aos::alerts::CoreAlert& val) const
    {
        Res   result  = CreateAlert(val);
        auto& pbAlert = *result.mutable_core_alert();

        pbAlert.set_core_component(val.mCoreComponent.CStr());
        pbAlert.set_message(val.mMessage.CStr());

        return result;
    }

    Res Visit(const aos::alerts::DownloadAlert& val) const
    {
        (void)val;

        return {};
    }

    Res Visit(const aos::alerts::SystemQuotaAlert& val) const
    {
        Res   result  = CreateAlert(val);
        auto& pbAlert = *result.mutable_system_quota_alert();

        pbAlert.set_parameter(val.mParameter.CStr());
        pbAlert.set_value(val.mValue);
        pbAlert.set_status(val.mStatus.CStr());

        return result;
    }

    Res Visit(const aos::alerts::InstanceQuotaAlert& val) const
    {
        Res   result  = CreateAlert(val);
        auto& pbAlert = *result.mutable_instance_quota_alert();

        ConvertToProto(val.mInstanceIdent, *pbAlert.mutable_instance());
        pbAlert.set_parameter(val.mParameter.CStr());
        pbAlert.set_value(val.mValue);
        pbAlert.set_status(val.mStatus.CStr());

        return result;
    }

    Res Visit(const aos::alerts::DeviceAllocateAlert& val) const
    {
        Res   result  = CreateAlert(val);
        auto& pbAlert = *result.mutable_device_allocate_alert();

        ConvertToProto(val.mInstanceIdent, *pbAlert.mutable_instance());
        pbAlert.set_device(val.mDevice.CStr());
        pbAlert.set_message(val.mMessage.CStr());

        return result;
    }

    Res Visit(const aos::alerts::ResourceValidateAlert& val) const
    {
        Res   result  = CreateAlert(val);
        auto& pbAlert = *result.mutable_resource_validate_alert();

        pbAlert.set_name(val.mName.CStr());

        for (const auto& error : val.mErrors) {
            *pbAlert.add_errors() = ConvertAosErrorToProto(error);
        }

        return result;
    }

    Res Visit(const aos::alerts::ServiceInstanceAlert& val) const
    {
        (void)val;

        return {};
    }
};

void ConvertToProto(const aos::alerts::AlertVariant& src, ::servicemanager::v4::Alert& dst)
{
    AlertVisitor visitor;

    dst = src.ApplyVisitor(visitor);
}

aos::InstanceIdent ConvertToAos(const common::v1::InstanceIdent& val)
{
    aos::InstanceIdent result;

    result.mServiceID = val.service_id().c_str();
    result.mSubjectID = val.subject_id().c_str();
    result.mInstance  = val.instance();

    return result;
}

aos::NetworkParameters ConvertToAos(const servicemanager::v4::NetworkParameters& val)
{
    aos::NetworkParameters result;

    result.mNetworkID = aos::String(val.network_id().c_str());
    result.mSubnet    = aos::String(val.subnet().c_str());
    result.mIP        = aos::String(val.ip().c_str());
    result.mVlanID    = val.vlan_id();

    for (const auto& dns : val.dns_servers()) {
        result.mDNSServers.PushBack(aos::String(dns.c_str()));
    }

    for (const auto& rule : val.rules()) {
        aos::FirewallRule firewallRule;

        firewallRule.mDstIP   = aos::String(rule.dst_ip().c_str());
        firewallRule.mDstPort = aos::String(rule.dst_port().c_str());
        firewallRule.mProto   = aos::String(rule.proto().c_str());
        firewallRule.mSrcIP   = aos::String(rule.src_ip().c_str());

        result.mFirewallRules.PushBack(aos::Move(firewallRule));
    }

    return result;
}

aos::InstanceInfo ConvertToAos(const servicemanager::v4::InstanceInfo& val)
{
    aos::InstanceInfo instanceInfo;

    instanceInfo.mInstanceIdent = utils::ConvertToAos(val.instance());
    instanceInfo.mUID           = val.uid();
    instanceInfo.mPriority      = val.priority();
    instanceInfo.mStoragePath   = aos::String(val.storage_path().c_str());
    instanceInfo.mStatePath     = aos::String(val.state_path().c_str());

    instanceInfo.mNetworkParameters = ConvertToAos(val.network_parameters());

    return instanceInfo;
}

aos::InstanceFilter ConvertToAos(const servicemanager::v4::InstanceFilter& val)
{
    aos::InstanceFilter instanceFilter;

    if (const auto& serviceID = val.service_id(); !serviceID.empty()) {
        instanceFilter.mServiceID.SetValue(aos::String(serviceID.c_str()));
    }

    if (const auto& subjectID = val.subject_id(); !subjectID.empty()) {
        instanceFilter.mSubjectID.SetValue(aos::String(subjectID.c_str()));
    }

    if (const auto instanceID = val.instance(); instanceID != -1) {
        instanceFilter.mInstance.SetValue(static_cast<uint64_t>(instanceID));
    }

    return instanceFilter;
}

aos::EnvVarInfo ConvertToAos(const servicemanager::v4::EnvVarInfo& val)
{
    aos::EnvVarInfo envVarInfo;

    envVarInfo.mName  = aos::String(val.name().c_str());
    envVarInfo.mValue = aos::String(val.value().c_str());
    envVarInfo.mTTL   = ConvertToAos(val.ttl());

    return envVarInfo;
}

aos::Optional<aos::Time> ConvertToAos(const google::protobuf::Timestamp& val)
{
    aos::Optional<aos::Time> result;

    if (val.seconds() > 0) {
        result.SetValue(aos::Time::Unix(val.seconds(), val.nanos()));
    }

    return result;
}

aos::ServiceInfo ConvertToAos(const ::servicemanager::v4::ServiceInfo& val)
{
    aos::ServiceInfo result;

    result.mServiceID  = aos::String(val.service_id().c_str());
    result.mProviderID = aos::String(val.provider_id().c_str());
    result.mVersion    = aos::String(val.version().c_str());
    result.mGID        = val.gid();
    result.mURL        = aos::String(val.url().c_str());
    result.mSHA256     = utils::ConvertByteArrayToAos(val.sha256());
    result.mSize       = val.size();

    return result;
}

aos::LayerInfo ConvertToAos(const ::servicemanager::v4::LayerInfo& val)
{
    aos::LayerInfo result;

    result.mLayerID     = aos::String(val.layer_id().c_str());
    result.mLayerDigest = aos::String(val.digest().c_str());
    result.mVersion     = aos::String(val.version().c_str());
    result.mURL         = aos::String(val.url().c_str());
    result.mSHA256      = utils::ConvertByteArrayToAos(val.sha256());
    result.mSize        = val.size();

    return result;
}

} // namespace aos::sm::utils
