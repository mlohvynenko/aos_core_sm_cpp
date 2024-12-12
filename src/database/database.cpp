/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <filesystem>

#include <Poco/Data/SQLite/Connector.h>
#include <Poco/Data/Session.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Path.h>

#include <utils/exception.hpp>
#include <utils/json.hpp>

#include "database.hpp"
#include "logger/logmodule.hpp"

using namespace Poco::Data::Keywords;

/***********************************************************************************************************************
 * Statics
 **********************************************************************************************************************/

namespace {

Poco::Data::BLOB ToBlob(const std::string& str)
{
    return Poco::Data::BLOB {reinterpret_cast<const uint8_t*>(str.c_str()), str.size()};
}

Poco::Data::BLOB ToBlob(const aos::String& str)
{
    return Poco::Data::BLOB {reinterpret_cast<const uint8_t*>(str.CStr()), str.Size()};
}

aos::Time ConvertTimestamp(uint64_t timestamp)
{
    const auto seconds = static_cast<int64_t>(timestamp / aos::Time::cSeconds);
    const auto nanos   = static_cast<int64_t>(timestamp % aos::Time::cSeconds);

    return aos::Time::Unix(seconds, nanos);
}

aos::cloudprotocol::EnvVarInfo ConvertEnvVarInfoFromJSON(const aos::common::utils::CaseInsensitiveObjectWrapper& object)
{
    aos::cloudprotocol::EnvVarInfo envVar;

    envVar.mTTL.Reset();

    const auto name  = object.GetValue<std::string>("name");
    const auto value = object.GetValue<std::string>("value");

    envVar.mName  = name.c_str();
    envVar.mValue = value.c_str();

    if (const auto ttl = object.GetOptionalValue<int64_t>("ttl").value_or(0); ttl > 0) {
        const auto time = ConvertTimestamp(ttl);

        envVar.mTTL.SetValue(time);
    }

    return envVar;
}

Poco::JSON::Array ConvertEnvVarsInstanceInfoArrayToJSON(
    const aos::cloudprotocol::EnvVarsInstanceInfoArray& envVarsInstanceInfos)
{
    Poco::JSON::Array result;

    for (const auto& envVarsInstanceInfo : envVarsInstanceInfos) {
        Poco::JSON::Object object;
        Poco::JSON::Object instanceFilter;

        if (envVarsInstanceInfo.mFilter.mServiceID.HasValue()) {
            instanceFilter.set("serviceID", envVarsInstanceInfo.mFilter.mServiceID.GetValue().CStr());
        }

        if (envVarsInstanceInfo.mFilter.mSubjectID.HasValue()) {
            instanceFilter.set("subjectID", envVarsInstanceInfo.mFilter.mSubjectID.GetValue().CStr());
        }

        if (envVarsInstanceInfo.mFilter.mInstance.HasValue()) {
            instanceFilter.set("instance", envVarsInstanceInfo.mFilter.mInstance.GetValue());
        }

        object.set("instanceFilter", instanceFilter);

        Poco::JSON::Array envVars;

        for (const auto& envVar : envVarsInstanceInfo.mVariables) {
            Poco::JSON::Object envVarObject;

            envVarObject.set("name", envVar.mName.CStr());
            envVarObject.set("value", envVar.mValue.CStr());

            if (envVar.mTTL.HasValue()) {
                envVarObject.set("ttl", envVar.mTTL.GetValue().UnixNano());
            }

            envVars.add(envVarObject);
        }

        object.set("envVars", envVars);

        result.add(object);
    }

    return result;
}

aos::cloudprotocol::EnvVarsInstanceInfo ConvertEnvVarsInfoFromJSON(
    const aos::common::utils::CaseInsensitiveObjectWrapper& object)
{
    aos::cloudprotocol::EnvVarsInstanceInfo result;

    if (object.Has("instanceFilter")) {
        const auto filter = object.GetObject("instanceFilter");

        if (filter.Has("serviceID")) {
            result.mFilter.mServiceID.SetValue(filter.GetValue<std::string>("serviceID").c_str());
        }

        if (filter.Has("subjectID")) {
            result.mFilter.mSubjectID.SetValue(filter.GetValue<std::string>("subjectID").c_str());
        }

        if (filter.Has("instance")) {
            result.mFilter.mInstance.SetValue(filter.GetValue<uint32_t>("instance"));
        }
    }

    const auto envVars = aos::common::utils::GetArrayValue<aos::cloudprotocol::EnvVarInfo>(
        object, "envVars", [&](const Poco::Dynamic::Var& value) {
            return ConvertEnvVarInfoFromJSON(
                aos::common::utils::CaseInsensitiveObjectWrapper(value.extract<Poco::JSON::Object::Ptr>()));
        });

    for (auto& envVar : envVars) {
        AOS_ERROR_CHECK_AND_THROW(
            "DB instance's envVar count exceeds application limit", result.mVariables.PushBack(aos::Move(envVar)));
    }

    return result;
}

aos::Error ConvertEnvVarsInstanceInfoArrayFromJSON(
    const std::string& src, aos::cloudprotocol::EnvVarsInstanceInfoArray& envVarsInstanceInfos)
{
    if (src.empty()) {
        return aos::ErrorEnum::eNone;
    }

    try {
        auto [parser, err] = aos::common::utils::ParseJson(src);

        if (!err.IsNone()) {
            return AOS_ERROR_WRAP(aos::Error(err, "Failed to parse envvars"));
        }

        auto items = parser.extract<Poco::JSON::Array::Ptr>();

        if (items.isNull()) {
            return aos::ErrorEnum::eNone;
        }

        for (const auto& item : *items) {
            const auto objectPtr = item.extract<Poco::JSON::Object::Ptr>();

            if (objectPtr.isNull()) {
                continue;
            }

            AOS_ERROR_CHECK_AND_THROW("DB instance's envvars count exceeds application limit",
                envVarsInstanceInfos.PushBack(
                    ConvertEnvVarsInfoFromJSON(aos::common::utils::CaseInsensitiveObjectWrapper(objectPtr))));
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(aos::Error(aos::ErrorEnum::eFailed, e.what()));
    }

    return aos::ErrorEnum::eNone;
}

Poco::JSON::Object ConvertNetworkParametersToJSON(const aos::NetworkParameters& networkParameters)
{
    Poco::JSON::Object object;
    Poco::JSON::Array  dnsServers;
    Poco::JSON::Array  firewallRules;

    object.set("networkID", networkParameters.mNetworkID.CStr());
    object.set("subnet", networkParameters.mSubnet.CStr());
    object.set("ip", networkParameters.mIP.CStr());
    object.set("vlanID", networkParameters.mVlanID);

    for (const auto& dnsServer : networkParameters.mDNSServers) {
        dnsServers.add(dnsServer.CStr());
    }

    object.set("dnsServers", dnsServers);

    for (const auto& firewallRule : networkParameters.mFirewallRules) {
        Poco::JSON::Object rule;

        rule.set("dstIp", firewallRule.mDstIP.CStr());
        rule.set("dstPort", firewallRule.mDstPort.CStr());
        rule.set("proto", firewallRule.mProto.CStr());
        rule.set("srcIp", firewallRule.mSrcIP.CStr());

        firewallRules.add(rule);
    }

    object.set("firewallRules", firewallRules);

    return object;
}

aos::Error ConvertNetworkParametersFromJSON(const Poco::JSON::Object& src, aos::NetworkParameters& networkParameters)
{
    try {
        networkParameters.mNetworkID = src.getValue<std::string>("networkID").c_str();
        networkParameters.mSubnet    = src.getValue<std::string>("subnet").c_str();
        networkParameters.mIP        = src.getValue<std::string>("ip").c_str();
        networkParameters.mVlanID    = src.getValue<uint64_t>("vlanID");
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(aos::Error(aos::ErrorEnum::eFailed, e.what()));
    }

    return aos::ErrorEnum::eNone;
}

class DBInstanceData {
public:
    using Fields = Poco::Tuple<std::string, std::string, std::string, uint64_t, uint32_t, uint64_t, std::string,
        std::string, Poco::Nullable<std::string>>;

    static aos::sm::launcher::InstanceData ToAos(const Fields& dbFields)
    {
        aos::sm::launcher::InstanceData result;

        result.mInstanceID = dbFields.get<Columns::eInstanceID>().c_str();

        result.mInstanceInfo.mInstanceIdent.mServiceID = dbFields.get<Columns::eServiceID>().c_str();
        result.mInstanceInfo.mInstanceIdent.mServiceID = dbFields.get<Columns::eServiceID>().c_str();
        result.mInstanceInfo.mInstanceIdent.mSubjectID = dbFields.get<Columns::eSubjectID>().c_str();
        result.mInstanceInfo.mInstanceIdent.mInstance  = dbFields.get<Columns::eInstance>();

        result.mInstanceInfo.mUID         = dbFields.get<Columns::eUID>();
        result.mInstanceInfo.mPriority    = dbFields.get<Columns::ePriority>();
        result.mInstanceInfo.mStoragePath = dbFields.get<Columns::eStoragePath>().c_str();
        result.mInstanceInfo.mStatePath   = dbFields.get<Columns::eStatePath>().c_str();

        const auto networkJson = dbFields.get<Columns::eNetwork>();
        if (networkJson.isNull()) {
            return result;
        }

        Poco::JSON::Parser parser;

        const auto ptr = parser.parse(networkJson.value()).extract<Poco::JSON::Object::Ptr>();
        if (ptr == nullptr) {
            AOS_ERROR_CHECK_AND_THROW("Failed to parse network json", AOS_ERROR_WRAP(aos::ErrorEnum::eFailed));
        }

        ConvertNetworkParametersFromJSON(*ptr, result.mInstanceInfo.mNetworkParameters);

        return result;
    }

private:
    enum Columns {
        eInstanceID = 0,
        eServiceID,
        eSubjectID,
        eInstance,
        eUID,
        ePriority,
        eStoragePath,
        eStatePath,
        eNetwork,
    };
};

class DBServiceData {
public:
    using Fields = Poco::Tuple<std::string, std::string, std::string, std::string, std::string, uint32_t, uint64_t,
        uint32_t, uint32_t>;

    static aos::sm::servicemanager::ServiceData ToAos(const Fields& dbFields)
    {
        aos::sm::servicemanager::ServiceData result;

        result.mServiceID      = dbFields.get<Columns::eServiceID>().c_str();
        result.mVersion        = dbFields.get<Columns::eVersion>().c_str();
        result.mProviderID     = dbFields.get<Columns::eProviderID>().c_str();
        result.mImagePath      = dbFields.get<Columns::eImagePath>().c_str();
        result.mManifestDigest = dbFields.get<Columns::eManifestDigest>().c_str();
        result.mState     = static_cast<aos::sm::servicemanager::ServiceStateEnum>(dbFields.get<Columns::eCached>());
        result.mTimestamp = ConvertTimestamp(dbFields.get<Columns::eTimestamp>());
        result.mSize      = dbFields.get<Columns::eSize>();
        result.mGID       = dbFields.get<Columns::eGID>();

        return result;
    }

private:
    enum Columns {
        eServiceID = 0,
        eVersion,
        eProviderID,
        eImagePath,
        eManifestDigest,
        eCached,
        eTimestamp,
        eSize,
        eGID,
    };
};

class DBNetworkInfo {
public:
    using Fields = Poco::Tuple<std::string, std::string, std::string, uint64_t, std::string>;

    static aos::sm::networkmanager::NetworkParameters ToAos(const Fields& dbFields)
    {
        aos::sm::networkmanager::NetworkParameters networkParameters;

        networkParameters.mNetworkID  = dbFields.get<Columns::eNetworkID>().c_str();
        networkParameters.mSubnet     = dbFields.get<Columns::eSubnet>().c_str();
        networkParameters.mIP         = dbFields.get<Columns::eIP>().c_str();
        networkParameters.mVlanID     = dbFields.get<Columns::eVlanID>();
        networkParameters.mVlanIfName = dbFields.get<Columns::eVlanIfName>().c_str();

        return networkParameters;
    }

private:
    enum Columns {
        eNetworkID = 0,
        eIP,
        eSubnet,
        eVlanID,
        eVlanIfName,
    };
};

class DBLayerData {
public:
    using Fields
        = Poco::Tuple<std::string, std::string, std::string, std::string, std::string, uint64_t, uint32_t, uint32_t>;

    static aos::sm::layermanager::LayerData ToAos(const Fields& dbFields)
    {
        aos::sm::layermanager::LayerData layer;

        layer.mLayerDigest = dbFields.get<Columns::eDigest>().c_str();
        layer.mLayerID     = dbFields.get<Columns::eLayerId>().c_str();
        layer.mPath        = dbFields.get<Columns::ePath>().c_str();
        layer.mOSVersion   = dbFields.get<Columns::eOSVersion>().c_str();
        layer.mVersion     = dbFields.get<Columns::eVersion>().c_str();
        layer.mSize        = dbFields.get<Columns::eSize>();
        layer.mState       = static_cast<aos::sm::layermanager::LayerStateEnum>(dbFields.get<Columns::eState>());
        layer.mTimestamp   = ConvertTimestamp(dbFields.get<Columns::eTimestamp>());

        return layer;
    }

private:
    enum Columns {
        eDigest = 0,
        eLayerId,
        ePath,
        eOSVersion,
        eVersion,
        eTimestamp,
        eState,
        eSize,
    };
};

} // namespace

namespace aos::sm::database {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Database::Database()
{
    Poco::Data::SQLite::Connector::registerConnector();
}

Database::~Database()
{
    LOG_DBG() << "Close database";

    if (mSession && mSession->isConnected()) {
        mSession->close();
    }

    Poco::Data::SQLite::Connector::unregisterConnector();
}

Error Database::Init(const std::string& workDir, const config::MigrationConfig& migrationConfig)
{
    LOG_DBG() << "Initializing database";

    if (mSession && mSession->isConnected()) {
        return ErrorEnum::eNone;
    }

    try {
        auto dirPath = std::filesystem::path(workDir);
        if (!std::filesystem::exists(dirPath)) {
            std::filesystem::create_directories(dirPath);
        }

        const auto dbPath = Poco::Path(workDir, cDBFileName);
        mSession          = std::make_unique<Poco::Data::Session>("SQLite", dbPath.toString());

        if (auto err = CreateConfigTable(); !err.IsNone()) {
            return err;
        }

        CreateTables();

        mMigration.emplace(*mSession, migrationConfig.mMigrationPath, migrationConfig.mMergedMigrationPath);
        mMigration->MigrateToVersion(sVersion);
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * sm::launcher::StorageItf implementation
 **********************************************************************************************************************/

Error Database::AddInstance(const sm::launcher::InstanceData& instance)
{
    LOG_DBG() << "Add instance: instanceID=" << instance.mInstanceID;

    try {
        const auto& instanceInfo = instance.mInstanceInfo;
        const auto  networkJson
            = common::utils::Stringify(ConvertNetworkParametersToJSON(instanceInfo.mNetworkParameters));

        *mSession << "INSERT INTO instances values(?, ?,  ?, ?, ?, ?, ?, ?, ?);", bind(instance.mInstanceID.CStr()),
            bind(instanceInfo.mInstanceIdent.mServiceID.CStr()), bind(instanceInfo.mInstanceIdent.mSubjectID.CStr()),
            bind(instanceInfo.mInstanceIdent.mInstance), bind(instanceInfo.mUID), bind(instanceInfo.mPriority),
            bind(instanceInfo.mStoragePath.CStr()), bind(instanceInfo.mStatePath.CStr()), bind(ToBlob(networkJson)),
            now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::UpdateInstance(const sm::launcher::InstanceData& instance)
{
    LOG_DBG() << "Update instance: instanceID=" << instance.mInstanceID;

    try {
        const auto& instanceInfo = instance.mInstanceInfo;
        const auto  networkJson
            = common::utils::Stringify(ConvertNetworkParametersToJSON(instanceInfo.mNetworkParameters));

        Poco::Data::Statement statement {*mSession};

        statement << "UPDATE instances SET "
                     "serviceID = ?, subjectID = ?, instance = ?, "
                     "uid = ?, priority = ?, storagePath = ?, statePath = ?, network = ? "
                     "WHERE instanceID = ?;",
            bind(instanceInfo.mInstanceIdent.mServiceID.CStr()), bind(instanceInfo.mInstanceIdent.mSubjectID.CStr()),
            bind(instanceInfo.mInstanceIdent.mInstance), bind(instanceInfo.mUID), bind(instanceInfo.mPriority),
            bind(instanceInfo.mStoragePath.CStr()), bind(instanceInfo.mStatePath.CStr()), bind(ToBlob(networkJson)),
            bind(instance.mInstanceID.CStr());

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::RemoveInstance(const String& instanceID)
{
    LOG_DBG() << "Remove instance: instanceID=" << instanceID;

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "DELETE FROM instances WHERE instanceID = ?;", bind(instanceID.CStr());

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetAllInstances(Array<sm::launcher::InstanceData>& instances)
{
    LOG_DBG() << "Get all instances";

    try {
        std::vector<DBInstanceData::Fields> result;

        *mSession << "SELECT * FROM instances;", into(result), now;

        for (const auto& info : result) {
            if (auto err = instances.PushBack(DBInstanceData::ToAos(info)); !err.IsNone()) {
                return AOS_ERROR_WRAP(Error(err, "db instances count exceeds application limit"));
            }
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

RetWithError<uint64_t> Database::GetOperationVersion() const
{
    RetWithError<uint64_t> result {0, ErrorEnum::eNone};

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "SELECT operationVersion FROM config;", into(result.mValue);

        if (statement.execute() == 0) {
            return {0, ErrorEnum::eNotFound};
        }

        LOG_DBG() << "Get operation version: version=" << result.mValue;
    } catch (const Poco::Exception& e) {
        result.mError = AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return result;
};

Error Database::SetOperationVersion(uint64_t version)
{
    LOG_DBG() << "Set operation version: version=" << version;

    try {
        *mSession << "UPDATE config SET operationVersion = ?;", use(version), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetOverrideEnvVars(cloudprotocol::EnvVarsInstanceInfoArray& envVarsInstanceInfos) const
{
    LOG_DBG() << "Get override env vars";

    try {
        std::string envVarsJson;

        *mSession << "SELECT envvars FROM config;", into(envVarsJson), now;

        return ConvertEnvVarsInstanceInfoArrayFromJSON(envVarsJson, envVarsInstanceInfos);
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::SetOverrideEnvVars(const cloudprotocol::EnvVarsInstanceInfoArray& envVarsInstanceInfos)
{
    LOG_DBG() << "Set override env vars";

    try {
        const auto envVarInstanceInfosJson
            = common::utils::Stringify(ConvertEnvVarsInstanceInfoArrayToJSON(envVarsInstanceInfos));

        Poco::Data::Statement statement {*mSession};

        statement << "UPDATE config SET envvars = ?;", bind(envVarInstanceInfosJson);

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

RetWithError<Time> Database::GetOnlineTime() const
{
    RetWithError<Time> result {{}, ErrorEnum::eNone};

    try {
        Poco::Data::Statement statement {*mSession};

        uint64_t onlineTime {0};

        statement << "SELECT onlineTime FROM config;", into(onlineTime), now;

        if (statement.execute() == 0) {
            return {Time::Unix(0, 0), ErrorEnum::eNotFound};
        }

        result.mValue = ConvertTimestamp(onlineTime);

        LOG_DBG() << "Get online time: time=" << result.mValue;
    } catch (const Poco::Exception& e) {
        result.mError = AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return result;
}

Error Database::SetOnlineTime(const Time& time)
{
    LOG_DBG() << "Set online time: time=" << time;

    try {
        *mSession << "UPDATE config SET onlineTime = ?;", bind(time.UnixNano()), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * sm::servicemanager::StorageItf implementation
 **********************************************************************************************************************/

Error Database::AddService(const sm::servicemanager::ServiceData& service)
{
    LOG_DBG() << "Add service: serviceID=" << service.mServiceID << ", version=" << service.mVersion;

    try {
        *mSession << "INSERT INTO services values(?, ?, ?, ?, ?, ?, ?, ?, ?);", bind(service.mServiceID.CStr()),
            bind(service.mVersion.CStr()), bind(service.mProviderID.CStr()), bind(service.mImagePath.CStr()),
            bind(ToBlob(service.mManifestDigest)), bind(static_cast<uint32_t>(service.mState.GetValue())),
            bind(service.mTimestamp.UnixNano()), bind(service.mSize), bind(service.mGID), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetServiceVersions(const String& serviceID, Array<sm::servicemanager::ServiceData>& services)
{
    LOG_DBG() << "Get service versions: serviceID=" << serviceID;

    RetWithError<sm::servicemanager::ServiceData> result {{}, ErrorEnum::eNone};

    try {
        Poco::Data::Statement statement {*mSession};

        std::vector<DBServiceData::Fields> dbResults;

        statement << "SELECT * FROM services WHERE id = ?;", bind(serviceID.CStr()), into(dbResults);

        if (statement.execute() == 0) {
            return ErrorEnum::eNotFound;
        }

        for (const auto& dbResult : dbResults) {
            if (auto err = services.PushBack(DBServiceData::ToAos(dbResult)); !err.IsNone()) {
                return AOS_ERROR_WRAP(Error(err, "db services count exceeds application limit"));
            }
        }
    } catch (const Poco::Exception& e) {
        result.mError = AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::UpdateService(const sm::servicemanager::ServiceData& service)
{
    LOG_DBG() << "Update service: serviceID=" << service.mServiceID << ", version=" << service.mVersion
              << ", state=" << service.mState;

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "UPDATE services SET providerID = ?, imagePath = ?,"
                     "manifestDigest = ?, state = ?, timestamp = ?, size = ?, GID = ? "
                     "WHERE id = ? AND version = ?;",
            bind(service.mProviderID.CStr()), bind(service.mImagePath.CStr()), bind(ToBlob(service.mManifestDigest)),
            bind(static_cast<uint32_t>(service.mState.GetValue())), bind(service.mTimestamp.UnixNano()),
            bind(service.mSize), bind(service.mGID), bind(service.mServiceID.CStr()), bind(service.mVersion.CStr());

        if (statement.execute() == 0) {
            return ErrorEnum::eNotFound;
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::RemoveService(const String& serviceID, const String& version)
{
    LOG_DBG() << "Remove service: serviceID=" << serviceID << ", version=" << version;

    try {
        *mSession << "DELETE FROM services WHERE id = ? AND version = ?;", bind(serviceID.CStr()), bind(version.CStr()),
            now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetAllServices(Array<sm::servicemanager::ServiceData>& services)
{
    LOG_DBG() << "Get all services";

    try {
        std::vector<DBServiceData::Fields> dbResult;

        *mSession << "SELECT * FROM services;", into(dbResult), now;

        for (const auto& service : dbResult) {
            if (auto err = services.PushBack(DBServiceData::ToAos(service)); !err.IsNone()) {
                return AOS_ERROR_WRAP(Error(err, "db services count exceeds application limit"));
            }
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * sm::networkmanager::StorageItf implementation
 **********************************************************************************************************************/

Error Database::RemoveNetworkInfo(const String& networkID)
{
    LOG_DBG() << "Remove network: networkID=" << networkID;

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "DELETE FROM network WHERE networkID = ?;", bind(networkID.CStr());

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::AddNetworkInfo(const sm::networkmanager::NetworkParameters& info)
{
    LOG_DBG() << "Add network info: networkID=" << info.mNetworkID;

    try {
        *mSession << "INSERT INTO network values(?, ?, ?, ?, ?);", bind(info.mNetworkID.CStr()), bind(info.mIP.CStr()),
            bind(info.mSubnet.CStr()), bind(info.mVlanID), bind(info.mVlanIfName.CStr()), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetNetworksInfo(Array<sm::networkmanager::NetworkParameters>& networks) const
{
    LOG_DBG() << "Get all networks";

    try {
        std::vector<DBNetworkInfo::Fields> result;

        *mSession << "SELECT * FROM network;", into(result), now;

        for (const auto& info : result) {
            if (auto err = networks.PushBack(DBNetworkInfo::ToAos(info)); !err.IsNone()) {
                return AOS_ERROR_WRAP(Error(err, "db network count exceeds application limit"));
            }
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::SetTrafficMonitorData(const String& chain, const Time& time, uint64_t value)
{
    LOG_DBG() << "Set traffic monitor data: chain=" << chain << ", time=" << time << ", value=" << value;

    try {
        *mSession << "INSERT OR REPLACE INTO trafficmonitor values(?, ?, ?);", bind(chain.CStr()),
            bind(time.UnixNano()), bind(value), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetTrafficMonitorData(const String& chain, Time& time, uint64_t& value) const
{
    LOG_DBG() << "Get traffic monitor data: chain=" << chain;

    try {
        Poco::Data::Statement statement {*mSession};

        uint64_t dbTime = 0;

        statement << "SELECT time, value FROM trafficmonitor WHERE chain = ?;", bind(chain.CStr()), into(dbTime),
            into(value);

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }

        time = ConvertTimestamp(dbTime);
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::RemoveTrafficMonitorData(const String& chain)
{
    LOG_DBG() << "Remove traffic monitor data: chain=" << chain;

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "DELETE FROM trafficmonitor WHERE chain = ?;", bind(chain.CStr());

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * sm::layermanager::StorageItf implementation
 **********************************************************************************************************************/

Error Database::AddLayer(const sm::layermanager::LayerData& layer)
{
    LOG_DBG() << "Add layer: digest=" << layer.mLayerDigest;

    try {
        *mSession << "INSERT INTO layers values(?, ?, ?, ?, ?, ?, ?, ?);", bind(layer.mLayerDigest.CStr()),
            bind(layer.mLayerID.CStr()), bind(layer.mPath.CStr()), bind(layer.mOSVersion.CStr()),
            bind(layer.mVersion.CStr()), bind(layer.mTimestamp.UnixNano()),
            bind(static_cast<uint32_t>(layer.mState.GetValue())), bind(layer.mSize), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::RemoveLayer(const String& digest)
{
    LOG_DBG() << "Remove layer: digest=" << digest;

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "DELETE FROM layers WHERE digest = ?;", bind(digest.CStr());

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetAllLayers(Array<sm::layermanager::LayerData>& layers) const
{
    LOG_DBG() << "Get all layers";

    try {
        std::vector<DBLayerData::Fields> result;

        *mSession << "SELECT * FROM layers;", into(result), now;

        for (const auto& info : result) {
            if (auto err = layers.PushBack(DBLayerData::ToAos(info)); !err.IsNone()) {
                return AOS_ERROR_WRAP(Error(err, "db layers count exceeds application limit"));
            }
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetLayer(const String& digest, sm::layermanager::LayerData& layer) const
{
    LOG_DBG() << "Get layer: digest=" << digest;

    try {
        DBLayerData::Fields result;

        Poco::Data::Statement statement {*mSession};

        statement << "SELECT * FROM layers WHERE digest = ?;", bind(digest.CStr()), into(result);

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }

        layer = DBLayerData::ToAos(result);
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::UpdateLayer(const sm::layermanager::LayerData& layer)
{
    LOG_DBG() << "Update layer: digest=" << layer.mLayerDigest << ", state=" << layer.mState;

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "UPDATE layers SET "
                     "layerId = ?, path = ?, osVersion = ?, version = ?, timestamp = ?, state = ?, size = ? "
                     "WHERE digest = ?;",
            bind(layer.mLayerID.CStr()), bind(layer.mPath.CStr()), bind(layer.mOSVersion.CStr()),
            bind(layer.mVersion.CStr()), bind(layer.mTimestamp.UnixNano()),
            bind(static_cast<uint32_t>(layer.mState.GetValue())), bind(layer.mSize), bind(layer.mLayerDigest.CStr());

        if (statement.execute() == 0) {
            return AOS_ERROR_WRAP(ErrorEnum::eNotFound);
        }
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * cloudprotocol::JournalAlertStorageItf implementation
 **********************************************************************************************************************/

Error Database::SetJournalCursor(const String& cursor)
{
    LOG_DBG() << "Set journal cursor: cursor=" << cursor;

    try {
        *mSession << "UPDATE config SET cursor = ?;", bind(cursor.CStr()), now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::GetJournalCursor(String& cursor) const
{
    try {
        std::string dbCursor;

        *mSession << "SELECT cursor FROM config;", into(dbCursor), now;

        cursor = dbCursor.c_str();

        LOG_DBG() << "Get journal cursor: cursor=" << cursor;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

RetWithError<bool> Database::TableExist(const std::string& tableName)
{
    size_t count {0};

    try {
        Poco::Data::Statement statement {*mSession};

        statement << "SELECT count(*) FROM sqlite_master WHERE name = ? and type='table'", bind(tableName), into(count);

        if (statement.execute() == 0) {
            return {false, ErrorEnum::eNotFound};
        }
    } catch (const Poco::Exception& e) {
        return {false, AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()))};
    }

    return {count > 0, ErrorEnum::eNone};
}

Error Database::DropAllTables()
{
    try {
        LOG_WRN() << "Dropping all tables";

        *mSession << "DROP TABLE IF EXISTS config;", now;
        *mSession << "DROP TABLE IF EXISTS network;", now;
        *mSession << "DROP TABLE IF EXISTS services;", now;
        *mSession << "DROP TABLE IF EXISTS trafficmonitor;", now;
        *mSession << "DROP TABLE IF EXISTS layers;", now;
        *mSession << "DROP TABLE IF EXISTS instances;", now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error Database::CreateConfigTable()
{
    auto [tableExists, err] = TableExist("config");

    if (!err.IsNone()) {
        return err;
    }

    if (tableExists) {
        uint64_t operationVersion {0};

        Tie(operationVersion, err) = GetOperationVersion();
        if (!err.IsNone()) {
            return err;
        }

        if (operationVersion == sm::launcher::Launcher::cOperationVersion) {
            return ErrorEnum::eNone;
        }

        if (err = DropAllTables(); !err.IsNone()) {
            return AOS_ERROR_WRAP(Error(err, "failed to drop all tables"));
        }
    }

    try {
        *mSession << "CREATE TABLE config ("
                     "operationVersion INTEGER, "
                     "cursor TEXT, "
                     "envvars TEXT, "
                     "onlineTime TIMESTAMP);",
            now;

        *mSession << "INSERT INTO config ("
                     "operationVersion, "
                     "onlineTime) values(?, ?);",
            bind(Poco::Tuple<uint32_t, uint64_t>(sm::launcher::Launcher::cOperationVersion, Time::Now().UnixNano())),
            now;
    } catch (const Poco::Exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

void Database::CreateTables()
{
    *mSession << "CREATE TABLE IF NOT EXISTS network ("
                 "networkID TEXT NOT NULL PRIMARY KEY, "
                 "ip TEXT, "
                 "subnet TEXT, "
                 "vlanID INTEGER, "
                 "vlanIfName TEXT);",
        now;

    *mSession << "CREATE TABLE IF NOT EXISTS services ("
                 "id TEXT NOT NULL , "
                 "version TEXT, "
                 "providerID TEXT, "
                 "imagePath TEXT, "
                 "manifestDigest BLOB, "
                 "state INTEGER, "
                 "timestamp TIMESTAMP, "
                 "size INTEGER, "
                 "GID INTEGER, "
                 "PRIMARY KEY(id, version));",
        now;

    *mSession << "CREATE TABLE IF NOT EXISTS trafficmonitor ("
                 "chain TEXT NOT NULL PRIMARY KEY, "
                 "time TIMESTAMP, "
                 "value INTEGER)",
        now;

    *mSession << "CREATE TABLE IF NOT EXISTS layers ("
                 "digest TEXT NOT NULL PRIMARY KEY, "
                 "layerId TEXT, "
                 "path TEXT, "
                 "osVersion TEXT, "
                 "version TEXT, "
                 "timestamp TIMESTAMP, "
                 "state INTEGER, "
                 "size INTEGER)",
        now;

    *mSession << "CREATE TABLE IF NOT EXISTS instances ("
                 "instanceID TEXT NOT NULL PRIMARY KEY, "
                 "serviceID TEXT, "
                 "subjectID TEXT, "
                 "instance INTEGER, "
                 "uid INTEGER, "
                 "priority INTEGER, "
                 "storagePath TEXT, "
                 "statePath TEXT, "
                 "network BLOB)",
        now;
}

} // namespace aos::sm::database
