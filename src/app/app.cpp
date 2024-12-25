/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <csignal>
#include <execinfo.h>
#include <iostream>

#include <Poco/SignalHandler.h>
#include <Poco/Util/HelpFormatter.h>
#include <systemd/sd-daemon.h>

#include <aos/common/version.hpp>
#include <utils/exception.hpp>

#include "config/config.hpp"
#include "logger/logmodule.hpp"
#include "version.hpp" // cppcheck-suppress missingInclude

#include "app.hpp"

namespace aos::sm::app {

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

namespace {

void SegmentationHandler(int sig)
{
    static constexpr auto cBacktraceSize = 32;

    void*  array[cBacktraceSize];
    size_t size;

    LOG_ERR() << "Segmentation fault";

    size = backtrace(array, cBacktraceSize);

    backtrace_symbols_fd(array, size, STDERR_FILENO);

    raise(sig);
}

void RegisterSegfaultSignal()
{
    struct sigaction act { };

    act.sa_handler = SegmentationHandler;
    act.sa_flags   = SA_RESETHAND;

    sigaction(SIGSEGV, &act, nullptr);
}

} // namespace

/***********************************************************************************************************************
 * Protected
 **********************************************************************************************************************/

void App::initialize(Application& self)
{
    if (mStopProcessing) {
        return;
    }

    Application::initialize(self);
    RegisterSegfaultSignal();
    InitAosCore();

    // Notify systemd

    auto ret = sd_notify(0, cSDNotifyReady);
    if (ret < 0) {
        AOS_ERROR_CHECK_AND_THROW("can't notify systemd", ret);
    }
}

void App::uninitialize()
{
    Application::uninitialize();
    StopAosCore();
}

void App::reinitialize(Application& self)
{
    Application::reinitialize(self);
}

int App::main(const ArgVec& args)
{
    (void)args;

    if (mStopProcessing) {
        return Application::EXIT_OK;
    }

    waitForTerminationRequest();

    return Application::EXIT_OK;
}

void App::defineOptions(Poco::Util::OptionSet& options)
{
    Application::defineOptions(options);

    options.addOption(Poco::Util::Option("help", "h", "displays help information")
                          .callback(Poco::Util::OptionCallback<App>(this, &App::HandleHelp)));
    options.addOption(Poco::Util::Option("version", "", "displays version information")
                          .callback(Poco::Util::OptionCallback<App>(this, &App::HandleVersion)));
    options.addOption(Poco::Util::Option("journal", "j", "redirects logs to systemd journal")
                          .callback(Poco::Util::OptionCallback<App>(this, &App::HandleJournal)));
    options.addOption(Poco::Util::Option("verbose", "v", "sets current log level")
                          .argument("${level}")
                          .callback(Poco::Util::OptionCallback<App>(this, &App::HandleLogLevel)));
    options.addOption(Poco::Util::Option("config", "c", "path to config file")
                          .argument("${file}")
                          .callback(Poco::Util::OptionCallback<App>(this, &App::HandleConfigFile)));
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

void App::InitAosCore()
{
    auto err = mLogger.Init();
    AOS_ERROR_CHECK_AND_THROW("can't initialize logger", err);

    LOG_INF() << "Initialize SM: version = " << AOS_CORE_SM_VERSION;

    // Initialize Aos modules

    auto config = std::make_shared<config::Config>();

    Tie(*config, err) = config::ParseConfig(mConfigFile.empty() ? cDefaultConfigFile : mConfigFile);
    AOS_ERROR_CHECK_AND_THROW("can't parse config", err);

    // Initialize crypto provider

    err = mCryptoProvider.Init();
    AOS_ERROR_CHECK_AND_THROW("can't initialize crypto provider", err);

    // Initialize cert loader

    err = mCertLoader.Init(mCryptoProvider, mPKCS11Manager);
    AOS_ERROR_CHECK_AND_THROW("can't initialize cert loader", err);

    // Initialize IAM client

    auto iamConfig = std::make_unique<common::iamclient::Config>();

    iamConfig->mCACert             = config->mCACert;
    iamConfig->mIAMPublicServerURL = config->mIAMPublicServerURL;

    err = mIAMClientPublic.Init(*iamConfig, mCertLoader, mCryptoProvider);
    AOS_ERROR_CHECK_AND_THROW("can't initialize public IAM client", err);

    auto nodeInfo = std::make_shared<NodeInfo>();

    err = mIAMClientPublic.GetNodeInfo(*nodeInfo);
    AOS_ERROR_CHECK_AND_THROW("can't get node info", err);

    err = mIAMClientPermissions.Init(config->mIAMProtectedServerURL, config->mCertStorage, mIAMClientPublic);
    AOS_ERROR_CHECK_AND_THROW("can't initialize permissions IAM client", err);

    // Initialize host device manager

    err = mHostDeviceManager.Init();
    AOS_ERROR_CHECK_AND_THROW("can't initialize host device manager", err);

    // Initialize resource manager

    err = mResourceManager.Init(
        mJSONProvider, mHostDeviceManager, nodeInfo->mNodeType, config->mNodeConfigFile.c_str());
    AOS_ERROR_CHECK_AND_THROW("can't initialize resource manager", err);

    // Initialize database

    err = mDatabase.Init(config->mWorkingDir, config->mMigration);
    AOS_ERROR_CHECK_AND_THROW("can't initialize database", err);

    // Initialize network manager

    err = mNetworkManager.Init(
        mDatabase, mCNI, mTrafficMonitor, mNamespaceManager, mNetworkInterfaceManager, config->mWorkingDir.c_str());
    AOS_ERROR_CHECK_AND_THROW("can't initialize network manager", err);

    // Initialize resource monitor

    err = mResourceMonitor.Init(mIAMClientPublic, mResourceUsageProvider, mSMClient, mSMClient);
    AOS_ERROR_CHECK_AND_THROW("can't initialize resource monitor", err);

    // Initialize service manager

    auto serviceManagerConfig = std::make_shared<sm::servicemanager::Config>();

    serviceManagerConfig->mServicesDir = config->mServicesDir.c_str();
    serviceManagerConfig->mDownloadDir = config->mDownloadDir.c_str();
    serviceManagerConfig->mTTL         = config->mServiceTTL.count();

    err = mServiceManager.Init(*serviceManagerConfig, mOCISpec, mDownloader, mDatabase, mServicesSpaceAllocator,
        mDownloadSpaceAllocator, mImageHandler);
    AOS_ERROR_CHECK_AND_THROW("can't initialize service manager", err);

    // Initialize layer manager

    auto layerManagerConfig = std::make_shared<sm::layermanager::Config>();

    layerManagerConfig->mLayersDir   = config->mLayersDir.c_str();
    layerManagerConfig->mDownloadDir = config->mDownloadDir.c_str();
    layerManagerConfig->mTTL         = config->mLayerTTL.count();

    err = mLayerManager.Init(*layerManagerConfig, mLayersSpaceAllocator, mDownloadSpaceAllocator, mDatabase,
        mDownloader, mImageHandler, mOCISpec);
    AOS_ERROR_CHECK_AND_THROW("can't initialize layer manager", err);

    // Initialize launcher

    auto launcherConfig = std::make_shared<sm::launcher::Config>();

    launcherConfig->mWorkDir    = config->mWorkingDir.c_str();
    launcherConfig->mStorageDir = config->mStorageDir.c_str();
    launcherConfig->mStateDir   = config->mStateDir.c_str();

    for (const auto& bind : config->mHostBinds) {
        err = launcherConfig->mHostBinds.EmplaceBack(bind.c_str());
        AOS_ERROR_CHECK_AND_THROW("can't add host bind", err);
    }

    for (const auto& host : config->mHosts) {
        err = launcherConfig->mHosts.EmplaceBack(Host {host.mIP.c_str(), host.mHostname.c_str()});
        AOS_ERROR_CHECK_AND_THROW("can't add host", err);
    }

    err = mLauncher.Init(*launcherConfig, mIAMClientPublic, mServiceManager, mLayerManager, mResourceManager,
        mNetworkManager, mIAMClientPermissions, mRunner, mResourceMonitor, mOCISpec, mSMClient, mSMClient, mDatabase);
    AOS_ERROR_CHECK_AND_THROW("can't initialize launcher", err);

    // Initialize SM client

    err = mSMClient.Init(*config, mIAMClientPublic, mIAMClientPublic, mResourceManager, mNetworkManager, mLogProvider,
        mResourceMonitor, mLauncher);
    AOS_ERROR_CHECK_AND_THROW("can't initialize SM client", err);
}

void App::StartAosCore()
{
    auto err = mSMClient.Start();
    AOS_ERROR_CHECK_AND_THROW("can't start SM client", err);

    err = mLauncher.Start();
    AOS_ERROR_CHECK_AND_THROW("can't start launcher", err);

    err = mLayerManager.Start();
    AOS_ERROR_CHECK_AND_THROW("can't start layer manager", err);

    err = mNetworkManager.Start();
    AOS_ERROR_CHECK_AND_THROW("can't start network manager", err);

    err = mResourceMonitor.Start();
    AOS_ERROR_CHECK_AND_THROW("can't start resource monitor", err);

    err = mServiceManager.Start();
    AOS_ERROR_CHECK_AND_THROW("can't start service manager", err);
}

void App::StopAosCore()
{
    auto err = mSMClient.Stop();
    AOS_ERROR_CHECK_AND_THROW("can't stop SM client", err);

    err = mLauncher.Stop();
    AOS_ERROR_CHECK_AND_THROW("can't stop launcher", err);

    err = mLayerManager.Stop();
    AOS_ERROR_CHECK_AND_THROW("can't stop layer manager", err);

    err = mNetworkManager.Stop();
    AOS_ERROR_CHECK_AND_THROW("can't stop network manager", err);

    err = mResourceMonitor.Stop();
    AOS_ERROR_CHECK_AND_THROW("can't stop resource monitor", err);

    err = mServiceManager.Stop();
    AOS_ERROR_CHECK_AND_THROW("can't stop service manager", err);
}

void App::HandleHelp(const std::string& name, const std::string& value)
{
    (void)name;
    (void)value;

    mStopProcessing = true;

    Poco::Util::HelpFormatter helpFormatter(options());

    helpFormatter.setCommand(commandName());
    helpFormatter.setUsage("[OPTIONS]");
    helpFormatter.setHeader("Aos SM manager service.");
    helpFormatter.format(std::cout);

    stopOptionsProcessing();
}

void App::HandleVersion(const std::string& name, const std::string& value)
{
    (void)name;
    (void)value;

    mStopProcessing = true;

    std::cout << "Aos IA manager version:   " << AOS_CORE_SM_VERSION << std::endl;
    std::cout << "Aos core library version: " << AOS_CORE_VERSION << std::endl;

    stopOptionsProcessing();
}

void App::HandleJournal(const std::string& name, const std::string& value)
{
    (void)name;
    (void)value;

    mLogger.SetBackend(aos::common::logger::Logger::Backend::eJournald);
}

void App::HandleLogLevel(const std::string& name, const std::string& value)
{
    (void)name;

    aos::LogLevel level;

    auto err = level.FromString(aos::String(value.c_str()));
    if (!err.IsNone()) {
        throw Poco::Exception("unsupported log level", value);
    }

    mLogger.SetLogLevel(level);
}

void App::HandleConfigFile(const std::string& name, const std::string& value)
{
    (void)name;

    mConfigFile = value;
}

} // namespace aos::sm::app
