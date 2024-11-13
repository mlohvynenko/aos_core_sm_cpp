/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RESOURCEMANAGER_MOCK_HPP_
#define RESOURCEMANAGER_MOCK_HPP_

#include <gmock/gmock.h>

#include <aos/sm/resourcemanager.hpp>

/**
 * Resource manager mock.
 */
class ResourceManagerMock : public aos::sm::resourcemanager::ResourceManagerItf {
public:
    MOCK_METHOD(aos::RetWithError<aos::StaticString<aos::cVersionLen>>, GetNodeConfigVersion, (), (const, override));
    MOCK_METHOD(aos::Error, GetDeviceInfo, (const aos::String&, aos::DeviceInfo&), (const, override));
    MOCK_METHOD(aos::Error, GetResourceInfo, (const aos::String&, aos::ResourceInfo&), (const, override));
    MOCK_METHOD(aos::Error, AllocateDevice, (const aos::String&, const aos::String&), (override));
    MOCK_METHOD(aos::Error, ReleaseDevice, (const aos::String&, const aos::String&), (override));
    MOCK_METHOD(aos::Error, ReleaseDevices, (const aos::String&), (override));
    MOCK_METHOD(aos::Error, GetDeviceInstances,
        (const aos::String&, aos::Array<aos::StaticString<aos::cInstanceIDLen>>&), (const override));
    MOCK_METHOD(aos::Error, CheckNodeConfig, (const aos::String&, const aos::String&), (const override));
    MOCK_METHOD(aos::Error, UpdateNodeConfig, (const aos::String&, const aos::String&), (override));
};

#endif
