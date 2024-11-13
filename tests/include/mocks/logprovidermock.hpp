/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LOGPROVIDER_MOCK_HPP_
#define LOGPROVIDER_MOCK_HPP_

#include <gmock/gmock.h>

#include <aos/sm/logprovider.hpp>

/**
 * Logs observer mock.
 */
class LogsObserverMock : public aos::sm::logprovider::LogsObserverItf {
public:
    MOCK_METHOD(aos::Error, OnLogReceived, (const aos::PushLog&), (override));
};

/**
 * Log provider mock.
 */
class LogProviderMock : public aos::sm::logprovider::LogProviderItf {
public:
    MOCK_METHOD(aos::Error, GetInstanceLog, (const aos::RequestLog&), (override));
    MOCK_METHOD(aos::Error, GetInstanceCrashLog, (const aos::RequestLog&), (override));
    MOCK_METHOD(aos::Error, GetSystemLog, (const aos::RequestLog&), (override));
    MOCK_METHOD(aos::Error, Subscribe, (aos::sm::logprovider::LogsObserverItf&), (override));
    MOCK_METHOD(aos::Error, Unsubscribe, (aos::sm::logprovider::LogsObserverItf&), (override));
};

#endif
