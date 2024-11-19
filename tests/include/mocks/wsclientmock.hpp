/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WS_CLIENT_MOCK_HPP_
#define WS_CLIENT_MOCK_HPP_

#include "visidentifier/wsclient.hpp"
#include <gmock/gmock.h>
#include <memory>

/**
 * Subjects observer mock.
 */
class WSClientMock : public WSClientItf {
public:
    MOCK_METHOD(void, Connect, (), (override));
    MOCK_METHOD(void, Close, (), (override));
    MOCK_METHOD(void, Disconnect, (), (override));
    MOCK_METHOD(std::string, GenerateRequestID, (), (override));
    MOCK_METHOD(WSClientEvent::Details, WaitForEvent, (), (override));
    MOCK_METHOD(ByteArray, SendRequest, (const std::string&, const ByteArray&), (override));
    MOCK_METHOD(void, AsyncSendMessage, (const ByteArray&), (override));
};

using WSClientMockPtr = std::shared_ptr<WSClientMock>;

#endif
