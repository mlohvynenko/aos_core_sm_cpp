/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <filesystem>

#include <gtest/gtest.h>

#include <aos/test/log.hpp>
#include <aos/test/utils.hpp>

#include "resourcemanager/resourcemanager.hpp"

using namespace testing;

namespace aos::sm::resourcemanager {

class ResourcemanagerTest : public Test {
public:
    void SetUp() override
    {
        test::InitLog();

        std::filesystem::create_directories("test/dev/dri/card0");
    }

    void TearDown() override { std::filesystem::remove_all("test"); }

    HostDeviceManager mHostDeviceManager;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(ResourcemanagerTest, CheckDevice)
{
    ASSERT_TRUE(mHostDeviceManager.Init().IsNone());

    auto err = mHostDeviceManager.CheckDevice("/dev/null");
    EXPECT_TRUE(err.IsNone()) << test::ErrorToStr(err);

    err = mHostDeviceManager.CheckDevice("/dev/null:/dev/test");
    EXPECT_TRUE(err.IsNone()) << test::ErrorToStr(err);

    err = mHostDeviceManager.CheckDevice("test/dev/dri/card0:/dev/dri/card0");
    EXPECT_TRUE(err.IsNone()) << test::ErrorToStr(err);
}

TEST_F(ResourcemanagerTest, CheckDeviceReturnsNotFound)
{
    ASSERT_TRUE(mHostDeviceManager.Init().IsNone());

    EXPECT_TRUE(mHostDeviceManager.CheckDevice("not found test folder").Is(ErrorEnum::eNotFound));
}

TEST_F(ResourcemanagerTest, CheckGroup)
{
    ASSERT_TRUE(mHostDeviceManager.Init().IsNone());

    EXPECT_TRUE(mHostDeviceManager.CheckGroup("root").IsNone());
}

TEST_F(ResourcemanagerTest, CheckGroupReturnsNotFound)
{
    ASSERT_TRUE(mHostDeviceManager.Init().IsNone());

    EXPECT_TRUE(mHostDeviceManager.CheckGroup("not found test group").Is(ErrorEnum::eNotFound));
}

} // namespace aos::sm::resourcemanager
