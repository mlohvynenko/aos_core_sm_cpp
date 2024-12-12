/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DATABASE_HPP_
#define DATABASE_HPP_

#include <memory>
#include <optional>
#include <string>

#include <aos/common/alerts/alerts.hpp>
#include <aos/common/cloudprotocol/alerts.hpp>
#include <aos/sm/launcher.hpp>
#include <aos/sm/layermanager.hpp>
#include <aos/sm/networkmanager.hpp>
#include <aos/sm/servicemanager.hpp>
#include <migration/migration.hpp>

#include "config/config.hpp"

namespace aos::sm::database {

class Database : public sm::launcher::StorageItf,
                 public sm::servicemanager::StorageItf,
                 public sm::networkmanager::StorageItf,
                 public sm::layermanager::StorageItf,
                 public alerts::StorageItf {
public:
    /**
     * Creates database instance.
     */
    Database();

    /**
     * Destructor.
     */
    ~Database();

    /**
     * Initializes certificate info storage.
     *
     * @param workDir working directory.
     * @param migrationConfig migration config.
     * @return Error.
     */
    Error Init(const std::string& workDir, const config::MigrationConfig& migrationConfig);

    // sm::launcher::StorageItf interface

    /**
     * Adds new instance to storage.
     *
     * @param instance instance to add.
     * @return Error.
     */
    Error AddInstance(const sm::launcher::InstanceData& instance) override;

    /**
     * Updates previously stored instance.
     *
     * @param instance instance to update.
     * @return Error.
     */
    Error UpdateInstance(const sm::launcher::InstanceData& instance) override;

    /**
     * Removes previously stored instance.
     *
     * @param instanceID instance ID to remove.
     * @return Error.
     */
    Error RemoveInstance(const String& instanceID) override;

    /**
     * Returns all stored instances.
     *
     * @param instances array to return stored instances.
     * @return Error.
     */
    Error GetAllInstances(Array<sm::launcher::InstanceData>& instances) override;

    /**
     * Returns operation version.
     *
     * @return RetWithError<uint64_t>.
     */
    RetWithError<uint64_t> GetOperationVersion() const override;

    /**
     * Sets operation version.
     *
     * @param version operation version.
     * @return Error.
     */
    Error SetOperationVersion(uint64_t version) override;

    /**
     * Returns instances's override environment variables array.
     *
     * @param envVarsInstanceInfos[out] instances's override environment variables array.
     * @return Error.
     */
    Error GetOverrideEnvVars(cloudprotocol::EnvVarsInstanceInfoArray& envVarsInstanceInfos) const override;

    /**
     * Sets instances's override environment variables array.
     *
     * @param envVarsInstanceInfos instances's override environment variables array.
     * @return Error.
     */
    Error SetOverrideEnvVars(const cloudprotocol::EnvVarsInstanceInfoArray& envVarsInstanceInfos) override;

    /**
     * Returns online time.
     *
     * @return RetWithError<Time>.
     */
    RetWithError<Time> GetOnlineTime() const override;

    /**
     * Sets online time.
     *
     * @param time online time.
     * @return Error.
     */
    Error SetOnlineTime(const Time& time) override;

    // sm::servicemanager::StorageItf interface

    /**
     * Adds new service to storage.
     *
     * @param service service to add.
     * @return Error.
     */
    Error AddService(const sm::servicemanager::ServiceData& service) override;

    /**
     * Returns service versions by service ID.
     *
     * @param serviceID service ID.
     * @param services[out] service version for the given id.
     * @return Error.
     */
    Error GetServiceVersions(const String& serviceID, Array<sm::servicemanager::ServiceData>& services) override;

    /**
     * Updates previously stored service.
     *
     * @param service service to update.
     * @return Error.
     */
    Error UpdateService(const sm::servicemanager::ServiceData& service) override;

    /**
     * Removes previously stored service.
     *
     * @param serviceID service ID to remove.
     * @param version Aos service version.
     * @return Error.
     */
    Error RemoveService(const String& serviceID, const String& version) override;

    /**
     * Returns all stored services.
     *
     * @param services array to return stored services.
     * @return Error.
     */
    Error GetAllServices(Array<sm::servicemanager::ServiceData>& services) override;

    // sm::networkmanager::StorageItf interface

    /**
     * Removes network info from storage.
     *
     * @param networkID network ID to remove.
     * @return Error.
     */
    Error RemoveNetworkInfo(const String& networkID) override;

    /**
     * Adds network info to storage.
     *
     * @param info network info.
     * @return Error.
     */
    Error AddNetworkInfo(const sm::networkmanager::NetworkParameters& info) override;

    /**
     * Returns network information.
     *
     * @param networks[out] network information result.
     * @return Error.
     */
    Error GetNetworksInfo(Array<sm::networkmanager::NetworkParameters>& networks) const override;

    /**
     * Sets traffic monitor data.
     *
     * @param chain chain.
     * @param time time.
     * @param value value.
     * @return Error.
     */
    Error SetTrafficMonitorData(const String& chain, const Time& time, uint64_t value) override;

    /**
     * Returns traffic monitor data.
     *
     * @param chain chain.
     * @param time[out] time.
     * @param value[out] value.
     * @return Error.
     */
    Error GetTrafficMonitorData(const String& chain, Time& time, uint64_t& value) const override;

    /**
     * Removes traffic monitor data.
     *
     * @param chain chain.
     * @return Error.
     */
    Error RemoveTrafficMonitorData(const String& chain) override;

    // sm::layermanager::StorageItf interface

    /**
     * Adds layer to storage.
     *
     * @param layer layer data to add.
     * @return Error.
     */
    Error AddLayer(const sm::layermanager::LayerData& layer) override;

    /**
     * Removes layer from storage.
     *
     * @param digest layer digest.
     * @return Error.
     */
    Error RemoveLayer(const String& digest) override;

    /**
     * Returns all stored layers.
     *
     * @param layers[out] array to return stored layers.
     * @return Error.
     */
    Error GetAllLayers(Array<sm::layermanager::LayerData>& layers) const override;

    /**
     * Returns layer data.
     *
     * @param digest layer digest.
     * @param[out] layer layer data.
     * @return Error.
     */
    Error GetLayer(const String& digest, sm::layermanager::LayerData& layer) const override;

    /**
     * Updates layer.
     *
     * @param layer layer data to update.
     * @return Error.
     */
    Error UpdateLayer(const sm::layermanager::LayerData& layer) override;

    // cloudprotocol::JournalAlertStorageItf interface

    /**
     * Sets journal cursor.
     *
     * @param cursor journal cursor.
     * @return Error.
     */
    Error SetJournalCursor(const String& cursor) override;

    /**
     * Gets journal cursor.
     *
     * @param cursor[out] journal cursor.
     * @return Error.
     */
    Error GetJournalCursor(String& cursor) const override;

private:
    static constexpr int  sVersion    = 0;
    static constexpr auto cDBFileName = "servicemanager.db";

    RetWithError<bool> TableExist(const std::string& tableName);
    Error              DropAllTables();
    Error              CreateConfigTable();
    void               CreateTables();

    mutable std::unique_ptr<Poco::Data::Session> mSession;
    std::optional<common::migration::Migration>  mMigration;
};

} // namespace aos::sm::database

#endif
