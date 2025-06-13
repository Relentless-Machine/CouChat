package com.couchat.device.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a user's device in the CouChat system.
 * This class maps to the 'devices' table in the database.
 */
public class Device {

    private final String deviceId;          // Primary Key, unique identifier for the device
    private final String userId;            // FK to users table
    private String deviceName;            // User-friendly name for the device
    private String passkeyCredentialId;   // The credential ID for WebAuthn/Passkey (can be unique)
    private String passkeyPublicKey;      // The public key part of the passkey credential
    private Integer passkeySignCount;     // Signature counter for the passkey
    private String devicePublicKey;       // Device-specific RSA public key (if different from passkey)
    private final Instant createdAt;
    private Instant lastActiveAt;

    /**
     * Constructor for creating a new device instance.
     *
     * @param userId The ID of the user this device belongs to.
     * @param deviceName A user-friendly name for this device.
     */
    public Device(String userId, String deviceName) {
        this.deviceId = UUID.randomUUID().toString(); // Or a hardware-derived ID if possible
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null.");
        this.deviceName = deviceName;
        this.createdAt = Instant.now();
        this.lastActiveAt = this.createdAt;
    }

    /**
     * Constructor for loading an existing device from the database.
     *
     * @param deviceId Unique ID of the device.
     * @param userId ID of the user this device belongs to.
     * @param deviceName User-friendly name for the device.
     * @param passkeyCredentialId Credential ID for Passkey.
     * @param passkeyPublicKey Public key for Passkey.
     * @param passkeySignCount Signature count for Passkey.
     * @param devicePublicKey Device-specific public key.
     * @param createdAt Timestamp of creation.
     * @param lastActiveAt Timestamp of last activity.
     */
    public Device(String deviceId, String userId, String deviceName,
                  String passkeyCredentialId, String passkeyPublicKey, Integer passkeySignCount,
                  String devicePublicKey, Instant createdAt, Instant lastActiveAt) {
        this.deviceId = Objects.requireNonNull(deviceId, "Device ID cannot be null.");
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null.");
        this.deviceName = deviceName;
        this.passkeyCredentialId = passkeyCredentialId;
        this.passkeyPublicKey = passkeyPublicKey;
        this.passkeySignCount = passkeySignCount;
        this.devicePublicKey = devicePublicKey;
        this.createdAt = Objects.requireNonNull(createdAt, "Creation timestamp cannot be null.");
        this.lastActiveAt = lastActiveAt;
    }

    // Getters
    public String getDeviceId() {
        return deviceId;
    }

    public String getUserId() {
        return userId;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public String getPasskeyCredentialId() {
        return passkeyCredentialId;
    }

    public String getPasskeyPublicKey() {
        return passkeyPublicKey;
    }

    public Integer getPasskeySignCount() {
        return passkeySignCount;
    }

    public String getDevicePublicKey() {
        return devicePublicKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastActiveAt() {
        return lastActiveAt;
    }

    // Setters for mutable fields
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public void setPasskeyCredentialId(String passkeyCredentialId) {
        this.passkeyCredentialId = passkeyCredentialId;
    }

    public void setPasskeyPublicKey(String passkeyPublicKey) {
        this.passkeyPublicKey = passkeyPublicKey;
    }

    public void setPasskeySignCount(Integer passkeySignCount) {
        this.passkeySignCount = passkeySignCount;
    }

    public void setDevicePublicKey(String devicePublicKey) {
        this.devicePublicKey = devicePublicKey;
    }

    public void setLastActiveAt(Instant lastActiveAt) {
        this.lastActiveAt = lastActiveAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Device device = (Device) o;
        return Objects.equals(deviceId, device.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceId);
    }

    @Override
    public String toString() {
        return "Device{" +
                "deviceId='" + deviceId + '\'' +
                ", userId='" + userId + '\'' +
                ", deviceName='" + deviceName + '\'' +
                ", passkeyCredentialId='" + passkeyCredentialId + '\'' +
                ", createdAt=" + createdAt +
                ", lastActiveAt=" + lastActiveAt +
                '}';
    }
}

