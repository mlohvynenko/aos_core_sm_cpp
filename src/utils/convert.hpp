/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CONVERT_HPP_
#define CONVERT_HPP_

#include <aos/common/alerts/alerts.hpp>
#include <aos/common/crypto.hpp>
#include <aos/common/monitoring/monitoring.hpp>
#include <aos/common/types.hpp>

#include <servicemanager/v4/servicemanager.grpc.pb.h>

namespace aos::sm::utils {

/**
 * Converts byte array to string.
 *
 * @param arr array to convert.
 * @return const aos::Array<uint8_t>.
 */
const aos::Array<uint8_t> ConvertByteArrayToAos(const std::string& arr);

/**
 * Converts aos string array to protobuf repeated string.
 *
 * @param src string to convert.
 * @param[out] dst destination repeated string.
 * @return void.
 */
template <size_t Size>
static void ConvertToProto(
    const aos::Array<aos::StaticString<Size>>& src, google::protobuf::RepeatedPtrField<std::string>& dst)
{
    for (const auto& val : src) {
        dst.Add(val.CStr());
    }
}

/**
 * Converts aos error to protobuf error.
 *
 * @param error aos error.
 * @return iamanager::v5::ErrorInfo.
 */
::common::v1::ErrorInfo ConvertAosErrorToProto(const aos::Error& error);

/**
 * Converts aos instance ident to protobuf.
 *
 * @param src instance ident to convert.
 * @param[out] dst protobuf instance ident.
 * @return void.
 */
void ConvertToProto(const aos::InstanceIdent& src, ::common::v1::InstanceIdent& dst);

/**
 * Converts aos push log to protobuf.
 *
 * @param src push log to convert.
 * @param[out] dst protobuf log data.
 * @return void.
 */
void ConvertToProto(const aos::PushLog& src, ::servicemanager::v4::LogData& dst);

/**
 * Converts aos monitoring data to protobuf.
 *
 * @param src monitoring data to convert.
 * @param timestamp monitoring data timestamp.
 * @param[out] dst protobuf monitoring data.
 * @return void.
 */
void ConvertToProto(
    const aos::monitoring::MonitoringData& src, const aos::Time& timestamp, ::servicemanager::v4::MonitoringData& dst);

/**
 * Converts aos node monitoring data to protobuf.
 *
 * @param src aos node monitoring.
 * @param[out] dst protobuf message.
 * @return void.
 */
template <typename T>
void ConvertToProto(const aos::monitoring::NodeMonitoringData& src, T& dst)
{
    ConvertToProto(src.mMonitoringData, src.mTimestamp, *dst.mutable_node_monitoring());

    for (const auto& instance : src.mServiceInstances) {
        auto& instanceMonitoring = *dst.add_instances_monitoring();

        ConvertToProto(instance.mInstanceIdent, *instanceMonitoring.mutable_instance());
        ConvertToProto(instance.mMonitoringData, src.mTimestamp, *instanceMonitoring.mutable_monitoring_data());
    }
}

/**
 * Converts aos instance status to protobuf.
 *
 * @param src instance status to convert.
 * @param[out] dst protobuf instance status.
 * @return void.
 */
void ConvertToProto(const aos::InstanceStatus& src, ::servicemanager::v4::InstanceStatus& dst);

/**
 * Converts aos instance filter to protobuf.
 *
 * @param src aos instance filter.
 * @param dst[out] protobuf instance filter.
 * @return void.
 */
void ConvertToProto(const aos::InstanceFilter& src, ::servicemanager::v4::InstanceFilter& dst);

/**
 * Converts aos env var status to protobuf.
 *
 * @param src aos env var status.
 * @param dst[out] protobuf env var status.
 * @return aos::EnvVarInfo.
 */
void ConvertToProto(const aos::EnvVarStatus& src, ::servicemanager::v4::EnvVarStatus& dst);

/**
 * Converts aos alerts to protobuf.
 *
 * @param src aos alert.
 * @param dst[out] protobuf alert.
 * @return void.
 */
void ConvertToProto(const aos::alerts::AlertVariant& src, ::servicemanager::v4::Alert& dst);

/**
 * Converts protobuf instance ident to aos.
 *
 * @param val protobuf instance ident.
 * @return aos::InstanceIdent.
 */
aos::InstanceIdent ConvertToAos(const ::common::v1::InstanceIdent& val);

/**
 * Converts protobuf network parameters to aos.
 *
 * @param val protobuf network parameters.
 * @return aos::NetworkParameters.
 */
aos::NetworkParameters ConvertToAos(const ::servicemanager::v4::NetworkParameters& val);

/**
 * Converts protobuf instance info to aos.
 *
 * @param val protobuf instance info.
 * @return aos::InstanceInfo.
 */
aos::InstanceInfo ConvertToAos(const ::servicemanager::v4::InstanceInfo& val);

/**
 * Converts protobuf instance filter to aos.
 *
 * @param val protobuf instance filter.
 * @return aos::InstanceFilter.
 */
aos::InstanceFilter ConvertToAos(const ::servicemanager::v4::InstanceFilter& val);

/**
 * Converts protobuf env var info to aos.
 *
 * @param val protobuf env var info.
 * @return aos::EnvVarInfo.
 */
aos::EnvVarInfo ConvertToAos(const ::servicemanager::v4::EnvVarInfo& val);

/**
 * Converts protobuf timestamp to aos.
 *
 * @param val protobuf timestamp.
 * @return aos::Optional<aos::Time>.
 */
aos::Optional<aos::Time> ConvertToAos(const google::protobuf::Timestamp& val);

/**
 * Converts service info to aos.
 *
 * @param val protobuf service info.
 * @return aos::ServiceInfo .
 */
aos::ServiceInfo ConvertToAos(const ::servicemanager::v4::ServiceInfo& val);

/**
 * Converts layer info to aos.
 *
 * @param val protobuf layer info.
 * @return aos::LayerInfo.
 */
aos::LayerInfo ConvertToAos(const ::servicemanager::v4::LayerInfo& val);

/**
 * Sets protobuf error message from aos.
 *
 * @param src aos error.
 * @param[out] dst protobuf message.
 * @return void.
 */
template <typename Message>
void SetErrorInfo(const aos::Error& src, Message& dst)
{
    if (!src.IsNone()) {
        *dst.mutable_error() = ConvertAosErrorToProto(src);
    } else {
        dst.clear_error();
    }
}

} // namespace aos::sm::utils

#endif
