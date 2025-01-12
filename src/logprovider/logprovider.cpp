/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <filesystem>

#include <systemd/sd-journal.h>
#undef LOG_ERR

#include <logger/logmodule.hpp>
#include <utils/exception.hpp>

#include "logprovider.hpp"

namespace aos::sm::logprovider {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error LogProvider::Init(const config::LoggingConfig& config, InstanceIDProviderItf& instanceProvider)
{
    LOG_INF() << "Init log provider";

    if (config.mMaxPartSize > cloudprotocol::cLogContentLen) {
        return Error(ErrorEnum::eInvalidArgument, "Log part size exceeds allowed content length");
    }

    mConfig           = config;
    mInstanceProvider = &instanceProvider;

    return ErrorEnum::eNone;
}

Error LogProvider::Start()
{
    LOG_INF() << "Start log provider";

    mStopped      = false;
    mWorkerThread = std::thread(&LogProvider::ProcessLogs, this);

    return ErrorEnum::eNone;
}

Error LogProvider::Stop()
{
    {
        std::unique_lock<std::mutex> lock {mMutex};

        if (mStopped) {
            return ErrorEnum::eNone;
        }

        LOG_INF() << "Stop log provider";

        mStopped = true;
        mCondVar.notify_all();
    }

    if (mWorkerThread.joinable()) {
        mWorkerThread.join();
    }

    return ErrorEnum::eNone;
}

LogProvider::~LogProvider()
{
    Stop();
}

Error LogProvider::GetInstanceLog(const cloudprotocol::RequestLog& request)
{
    LOG_DBG() << "Get instance log: logID=" << request.mLogID;

    auto [instanceIDs, err] = mInstanceProvider->GetInstanceIDs(request.mFilter.mInstanceFilter);
    if (!err.IsNone()) {
        SendErrorResponse(request.mLogID, err.Message());

        return err;
    }

    if (instanceIDs.empty()) {
        LOG_DBG() << "No instance ids for log request: logID=" << request.mLogID;

        SendEmptyResponse(request.mLogID, "no service instance found");

        return ErrorEnum::eNone;
    }

    ScheduleGetLog(instanceIDs, request.mLogID, request.mFilter.mFrom, request.mFilter.mTill);

    return ErrorEnum::eNone;
}

Error LogProvider::GetInstanceCrashLog(const cloudprotocol::RequestLog& request)
{
    LOG_DBG() << "Get instance crash log: logID=" << request.mLogID;

    auto [instanceIDs, err] = mInstanceProvider->GetInstanceIDs(request.mFilter.mInstanceFilter);
    if (!err.IsNone()) {
        SendErrorResponse(request.mLogID, err.Message());

        return AOS_ERROR_WRAP(err);
    }

    if (instanceIDs.empty()) {
        LOG_DBG() << "No instance ids for crash log request: logID=" << request.mLogID;

        SendEmptyResponse(request.mLogID, "no service instance found");

        return ErrorEnum::eNone;
    }

    ScheduleGetCrashLog(instanceIDs, request.mLogID, request.mFilter.mFrom, request.mFilter.mTill);

    return ErrorEnum::eNone;
}

Error LogProvider::GetSystemLog(const cloudprotocol::RequestLog& request)
{
    LOG_DBG() << "Get system log: logID=" << request.mLogID;

    ScheduleGetLog({}, request.mLogID, request.mFilter.mFrom, request.mFilter.mTill);

    return ErrorEnum::eNone;
}

Error LogProvider::Subscribe(LogObserverItf& observer)
{
    std::unique_lock<std::mutex> lock {mMutex};

    mLogReceiver = &observer;

    return ErrorEnum::eNone;
}

Error LogProvider::Unsubscribe(LogObserverItf& observer)
{
    (void)observer;

    std::unique_lock<std::mutex> lock {mMutex};

    mLogReceiver = nullptr;

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

std::shared_ptr<Archivator> LogProvider::CreateArchivator()
{
    return std::make_shared<Archivator>(*mLogReceiver, mConfig);
}

std::shared_ptr<JournalItf> LogProvider::CreateJournal()
{
    return std::make_shared<Journal>();
}

void LogProvider::ScheduleGetLog(const std::vector<std::string>& instanceIDs,
    const StaticString<cloudprotocol::cLogIDLen>& logID, const Optional<Time>& from, const Optional<Time>& till)
{
    std::unique_lock<std::mutex> lock {mMutex};

    mLogRequests.emplace(GetLogRequest {instanceIDs, logID, from, till, false});

    mCondVar.notify_one();
}

void LogProvider::ScheduleGetCrashLog(const std::vector<std::string>& instanceIDs,
    const StaticString<cloudprotocol::cLogIDLen>& logID, const Optional<Time>& from, const Optional<Time>& till)
{
    std::unique_lock<std::mutex> lock {mMutex};

    mLogRequests.emplace(GetLogRequest {instanceIDs, logID, from, till, true});

    mCondVar.notify_one();
}

void LogProvider::ProcessLogs()
{
    while (true) {
        GetLogRequest logRequest;

        {
            std::unique_lock<std::mutex> lock {mMutex};

            mCondVar.wait(lock, [this] { return mStopped || !mLogRequests.empty(); });

            if (mStopped) {
                break;
            }

            if (mLogRequests.empty()) {
                continue;
            }

            logRequest = mLogRequests.front();
            mLogRequests.pop();
        }

        try {
            if (logRequest.mCrashLog) {
                GetInstanceCrashLog(logRequest.mInstanceIDs, logRequest.mLogID, logRequest.mFrom, logRequest.mTill);
            } else {
                GetLog(logRequest.mInstanceIDs, logRequest.mLogID, logRequest.mFrom, logRequest.mTill);
            }
        } catch (const common::utils::AosException& e) {
            LOG_ERR() << "PushLog failed: logID=" << logRequest.mLogID << ", err=" << e.GetError();

            SendErrorResponse(logRequest.mLogID, e.what());
        } catch (const std::exception& e) {
            LOG_ERR() << "PushLog failed: logID=" << logRequest.mLogID << ", err=" << e.what();

            SendErrorResponse(logRequest.mLogID, e.what());
        }
    }
}

void LogProvider::GetLog(const std::vector<std::string>& instanceIDs,
    const StaticString<cloudprotocol::cLogIDLen>& logID, const Optional<Time>& from, const Optional<Time>& till)
{
    if (!mLogReceiver) {
        return;
    }

    auto journal       = CreateJournal();
    bool needUnitField = true;

    if (!instanceIDs.empty()) {
        needUnitField = false;

        AddServiceCgroupFilter(*journal, instanceIDs);
    }

    SeekToTime(*journal, from);

    auto archivator = CreateArchivator();

    ProcessJournalLogs(*journal, till, needUnitField, *archivator);

    AOS_ERROR_CHECK_AND_THROW("sending log failed", archivator->SendLog(logID));
}

void LogProvider::GetInstanceCrashLog(const std::vector<std::string>& instanceIDs,
    const StaticString<cloudprotocol::cLogIDLen>& logID, const Optional<Time>& from, const Optional<Time>& till)
{
    if (!mLogReceiver) {
        return;
    }

    auto journal = CreateJournal();

    AddUnitFilter(*journal, instanceIDs);

    if (till.HasValue()) {
        journal->SeekRealtime(till.GetValue());
    } else {
        journal->SeekTail();
    }

    Time crashTime = GetCrashTime(*journal, from);
    if (crashTime.IsZero()) {
        // No crash time found, send an empty response
        SendEmptyResponse(logID, "no instance crash found");

        return;
    }

    journal->AddDisjunction();

    AddServiceCgroupFilter(*journal, instanceIDs);

    auto archivator = CreateArchivator();

    ProcessJournalCrashLogs(*journal, crashTime, instanceIDs, *archivator);

    AOS_ERROR_CHECK_AND_THROW("sending log failed", archivator->SendLog(logID));
}

void LogProvider::SendErrorResponse(const String& logID, const std::string& errorMsg)
{
    cloudprotocol::PushLog response;

    response.mMessageType = cloudprotocol::LogMessageTypeEnum::ePushLog;
    response.mLogID       = logID;
    response.mStatus      = cloudprotocol::LogStatusEnum::eError;
    response.mErrorInfo   = Error(ErrorEnum::eFailed, errorMsg.c_str());
    response.mPartsCount  = 0;
    response.mPart        = 0;

    if (mLogReceiver) {
        mLogReceiver->OnLogReceived(response);
    }
}

void LogProvider::SendEmptyResponse(const String& logID, const std::string& errorMsg)
{
    cloudprotocol::PushLog response;

    response.mMessageType = cloudprotocol::LogMessageTypeEnum::ePushLog;
    response.mLogID       = logID;
    response.mStatus      = cloudprotocol::LogStatusEnum::eAbsent;
    response.mPartsCount  = 1;
    response.mPart        = 1;
    response.mErrorInfo   = Error(ErrorEnum::eNone, errorMsg.c_str());

    if (mLogReceiver) {
        mLogReceiver->OnLogReceived(response);
    }
}

void LogProvider::AddServiceCgroupFilter(JournalItf& journal, const std::vector<std::string>& instanceIDs)
{
    for (const auto& instanceID : instanceIDs) {
        // for supporting cgroup v1
        // format: /system.slice/system-aos@service.slice/aos-service@AOS_INSTANCE_ID.service
        std::string cgroupV1Filter
            = std::string("_SYSTEMD_CGROUP=/system.slice/system-aos\\x2dservice.slice/aos-service@") + instanceID
            + ".service";
        journal.AddMatch(cgroupV1Filter);

        // for supporting cgroup v2
        // format: /system.slice/system-aos@service.slice/AOS_INSTANCE_ID
        std::string cgroupV2Filter
            = std::string("_SYSTEMD_CGROUP=/system.slice/system-aos\\x2dservice.slice/") + instanceID;
        journal.AddMatch(cgroupV2Filter);
    }
}

void LogProvider::AddUnitFilter(JournalItf& journal, const std::vector<std::string>& instanceIDs)
{
    for (const auto& instanceID : instanceIDs) {
        std::string unitName = std::string("aos-service@") + instanceID + ".service";
        std::string filter   = "UNIT=" + unitName;

        journal.AddMatch(filter);
    }
}

void LogProvider::SeekToTime(JournalItf& journal, const Optional<Time>& from)
{
    if (from.HasValue()) {
        journal.SeekRealtime(from.GetValue());
    } else {
        journal.SeekHead();
    }
}

void LogProvider::ProcessJournalLogs(
    JournalItf& journal, Optional<Time> till, bool needUnitField, Archivator& archivator)
{
    while (journal.Next()) {
        auto entry = journal.GetEntry();

        if (till.HasValue() && entry.mRealTime.UnixNano() > till.GetValue().UnixNano()) {
            return;
        }

        auto log = FormatLogEntry(entry, needUnitField);

        AOS_ERROR_CHECK_AND_THROW("adding log failed", archivator.AddLog(log));
    }
}

void LogProvider::ProcessJournalCrashLogs(
    JournalItf& journal, Time crashTime, const std::vector<std::string>& instanceIDs, Archivator& archivator)
{
    while (journal.Next()) {
        auto entry = journal.GetEntry();

        if (entry.mMonotonicTime.UnixNano() > crashTime.UnixNano()) {
            break;
        }

        for (const auto& instance : instanceIDs) {
            auto unitName      = MakeUnitNameFromInstanceID(instance);
            auto unitNameInLog = GetUnitNameFromLog(entry);

            if (unitNameInLog.find(unitName) != std::string::npos) {
                auto log = FormatLogEntry(entry, false);

                AOS_ERROR_CHECK_AND_THROW("adding log failed", archivator.AddLog(log));
                break;
            }
        }
    }
}

std::string LogProvider::FormatLogEntry(const JournalEntry& journalEntry, bool addUnit)
{
    auto [logEntryTimeStr, err] = journalEntry.mRealTime.ToString();
    AOS_ERROR_CHECK_AND_THROW("time formatting failed", err);

    std::ostringstream oss;

    if (addUnit) {
        oss << logEntryTimeStr.CStr() << " " << journalEntry.mSystemdUnit << " " << journalEntry.mMessage << "\n";
    } else {
        oss << logEntryTimeStr.CStr() << " " << journalEntry.mMessage << " \n";
    }

    return oss.str();
}

Time LogProvider::GetCrashTime(JournalItf& journal, const Optional<Time>& from)
{
    Time crashTime;

    while (journal.Previous()) {
        auto entry = journal.GetEntry();

        if (from.HasValue() && entry.mRealTime.UnixNano() <= from.GetValue().UnixNano()) {
            break;
        }

        if (crashTime.IsZero() && entry.mMessage.find("process exited") != std::string::npos) {
            crashTime = entry.mMonotonicTime;

            LOG_DBG() << "Crash detected: time=" << entry.mRealTime.ToString().mValue;
        } else if (entry.mMessage.find("Started") == 0) {
            break;
        }
    }

    return crashTime;
}

std::string LogProvider::GetUnitNameFromLog(const JournalEntry& journalEntry)
{
    std::string unitName = std::filesystem::path(journalEntry.mSystemdCGroup).filename().string();

    if (unitName.find(cAOSServicePrefix) == std::string::npos) {
        // with cgroup v2 logs from container do not contains _SYSTEMD_UNIT due to restrictions
        // that's why id should be checked via _SYSTEMD_CGROUP
        // format: /system.slice/system-aos@service.slice/AOS_INSTANCE_ID

        return cAOSServicePrefix + unitName + ".service";
    }

    return unitName;
}

std::string LogProvider::MakeUnitNameFromInstanceID(const std::string& instanceID)
{
    return std::string(cAOSServicePrefix) + instanceID + ".service";
}

} // namespace aos::sm::logprovider