package com.couchat.repository;

import com.couchat.device.model.Device;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for {@link Device} entities.
 * Defines a contract for data access operations related to user devices.
 */
public interface DeviceRepository {

    /**
     * Saves a new device or updates an existing one in the database.
     *
     * @param device The {@link Device} object to save. Must not be null.
     * @return The saved {@link Device} object.
     */
    Device save(Device device);

    /**
     * Finds a device by its unique ID.
     *
     * @param deviceId The ID of the device to find. Must not be null.
     * @return An {@link Optional} containing the {@link Device} if found, or an empty Optional otherwise.
     */
    Optional<Device> findById(String deviceId);

    /**
     * Finds a device by its Passkey Credential ID.
     *
     * @param credentialId The Passkey Credential ID. Must not be null.
     * @return An {@link Optional} containing the {@link Device} if found.
     */
    Optional<Device> findByPasskeyCredentialId(String credentialId);

    /**
     * Retrieves all devices registered to a specific user.
     *
     * @param userId The ID of the user. Must not be null.
     * @return A list of {@link Device} objects belonging to the user.
     */
    List<Device> findByUserId(String userId);

    /**
     * Deletes a device by its unique ID.
     *
     * @param deviceId The ID of the device to delete. Must not be null.
     * @return true if the device was deleted successfully, false otherwise.
     */
    boolean deleteById(String deviceId);

    /**
     * Deletes a specific device belonging to a specific user.
     *
     * @param userId The ID of the user. Must not be null.
     * @param deviceId The ID of the device to delete. Must not be null.
     * @return true if the device was deleted successfully, false otherwise.
     */
    boolean deleteByUserIdAndDeviceId(String userId, String deviceId);

    /**
     * Updates the last active timestamp for a device.
     *
     * @param deviceId The ID of the device to update. Must not be null.
     * @param lastActiveAt The new last active timestamp. Must not be null.
     * @return true if the update was successful, false otherwise.
     */
    boolean updateLastActiveAt(String deviceId, java.time.Instant lastActiveAt);
}

