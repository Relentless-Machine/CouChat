package com.couchat.device.service;

import com.couchat.device.model.Device;
import com.couchat.repository.DeviceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Service layer for device-related operations.
 */
@Service
public class DeviceService {

    private static final Logger logger = LoggerFactory.getLogger(DeviceService.class);
    private final DeviceRepository deviceRepository;

    @Autowired
    public DeviceService(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    /**
     * Registers a new device for a user or updates an existing one.
     *
     * @param device The device to register or update.
     * @return The saved device.
     */
    public Device registerOrUpdateDevice(Device device) {
        logger.info("DeviceService.registerOrUpdateDevice called for deviceId: {}", device.getDeviceId());
        // TODO: Add validation, e.g., ensure userId exists
        return deviceRepository.save(device);
    }

    /**
     * Finds a device by its ID.
     *
     * @param deviceId The device ID.
     * @return Optional of Device.
     */
    public Optional<Device> findDeviceById(String deviceId) {
        logger.info("DeviceService.findDeviceById called for deviceId: {}", deviceId);
        return deviceRepository.findById(deviceId);
    }

    /**
     * Finds a device by its Passkey Credential ID.
     *
     * @param credentialId The Passkey Credential ID.
     * @return Optional of Device.
     */
    public Optional<Device> findDeviceByPasskeyCredentialId(String credentialId) {
        logger.info("DeviceService.findDeviceByPasskeyCredentialId called for credentialId: {}", credentialId);
        return deviceRepository.findByPasskeyCredentialId(credentialId);
    }

    /**
     * Retrieves all devices for a given user.
     *
     * @param userId The user ID.
     * @return List of devices.
     */
    public List<Device> getDevicesByUserId(String userId) {
        logger.info("DeviceService.getDevicesByUserId called for userId: {}", userId);
        return deviceRepository.findByUserId(userId);
    }

    /**
     * Deletes a specific device.
     *
     * @param deviceId The ID of the device to delete.
     * @param userId The ID of the user making the request (for permission check).
     * @return true if successful.
     */
    @Transactional
    public boolean deleteDevice(String deviceId, String userId) {
        logger.info("DeviceService.deleteDevice called for deviceId: {} by user: {}", deviceId, userId);
        Optional<Device> deviceOpt = deviceRepository.findById(deviceId);
        if (deviceOpt.isPresent()) {
            if (!deviceOpt.get().getUserId().equals(userId)) {
                // Or throw a security exception
                logger.warn("User {} attempted to delete device {} not belonging to them.", userId, deviceId);
                return false;
            }
            return deviceRepository.deleteById(deviceId);
        }
        return false;
    }

    /**
     * Updates the last active timestamp for a device.
     *
     * @param deviceId The device ID.
     */
    public void updateDeviceLastActive(String deviceId) {
        logger.info("DeviceService.updateDeviceLastActive called for deviceId: {}", deviceId);
        deviceRepository.updateLastActiveAt(deviceId, Instant.now());
    }
}

