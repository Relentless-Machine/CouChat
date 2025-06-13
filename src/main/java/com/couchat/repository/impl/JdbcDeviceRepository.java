package com.couchat.repository.impl;

import com.couchat.device.model.Device;
import com.couchat.repository.DeviceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * JDBC implementation of the {@link DeviceRepository} interface.
 * Provides stub or minimal implementations for now to allow application context to load.
 */
@Repository
public class JdbcDeviceRepository implements DeviceRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcDeviceRepository.class);
    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<Device> deviceRowMapper = (rs, rowNum) -> new Device(
            rs.getString("device_id"),
            rs.getString("user_id"),
            rs.getString("device_name"),
            rs.getString("passkey_credential_id"),
            rs.getString("passkey_public_key"),
            (Integer) rs.getObject("passkey_sign_count"), // getObject to handle potential SQL NULL for Integer
            rs.getString("device_public_key"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("last_active_at") != null ? rs.getTimestamp("last_active_at").toInstant() : null
    );

    @Autowired
    public JdbcDeviceRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public Device save(Device device) {
        logger.info("JdbcDeviceRepository.save called for deviceId: {}", device.getDeviceId());
        if (device == null) {
            throw new IllegalArgumentException("Device to save cannot be null.");
        }
        String sql = "INSERT INTO devices (device_id, user_id, device_name, passkey_credential_id, passkey_public_key, " +
                     "passkey_sign_count, device_public_key, created_at, last_active_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(device_id) DO UPDATE SET " +
                     "user_id = excluded.user_id, " +
                     "device_name = excluded.device_name, " +
                     "passkey_credential_id = excluded.passkey_credential_id, " +
                     "passkey_public_key = excluded.passkey_public_key, " +
                     "passkey_sign_count = excluded.passkey_sign_count, " +
                     "device_public_key = excluded.device_public_key, " +
                     "last_active_at = excluded.last_active_at";
        try {
            jdbcTemplate.update(sql,
                    device.getDeviceId(),
                    device.getUserId(),
                    device.getDeviceName(),
                    device.getPasskeyCredentialId(),
                    device.getPasskeyPublicKey(),
                    device.getPasskeySignCount(),
                    device.getDevicePublicKey(),
                    Timestamp.from(device.getCreatedAt()),
                    device.getLastActiveAt() != null ? Timestamp.from(device.getLastActiveAt()) : null
            );
            return device;
        } catch (DataAccessException e) {
            logger.error("Error saving device with ID {}: {}", device.getDeviceId(), e.getMessage(), e);
            throw new RuntimeException("Failed to save device", e);
        }
    }

    @Override
    public Optional<Device> findById(String deviceId) {
        logger.info("JdbcDeviceRepository.findById called for deviceId: {}", deviceId);
        if (deviceId == null) return Optional.empty();
        String sql = "SELECT * FROM devices WHERE device_id = ?";
        try {
            Device device = jdbcTemplate.queryForObject(sql, new Object[]{deviceId}, deviceRowMapper);
            return Optional.ofNullable(device);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding device by ID {}: {}", deviceId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<Device> findByPasskeyCredentialId(String credentialId) {
        logger.info("JdbcDeviceRepository.findByPasskeyCredentialId called for credentialId: {}", credentialId);
        if (credentialId == null) return Optional.empty();
        String sql = "SELECT * FROM devices WHERE passkey_credential_id = ?";
        try {
            Device device = jdbcTemplate.queryForObject(sql, new Object[]{credentialId}, deviceRowMapper);
            return Optional.ofNullable(device);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding device by passkey credential ID {}: {}", credentialId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public List<Device> findByUserId(String userId) {
        logger.info("JdbcDeviceRepository.findByUserId called for userId: {}", userId);
        if (userId == null) return Collections.emptyList();
        String sql = "SELECT * FROM devices WHERE user_id = ? ORDER BY last_active_at DESC";
        try {
            return jdbcTemplate.query(sql, new Object[]{userId}, deviceRowMapper);
        } catch (DataAccessException e) {
            logger.error("Error finding devices by user ID {}: {}", userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public boolean deleteById(String deviceId) {
        logger.info("JdbcDeviceRepository.deleteById called for deviceId: {}", deviceId);
        if (deviceId == null) return false;
        String sql = "DELETE FROM devices WHERE device_id = ?";
        try {
            return jdbcTemplate.update(sql, deviceId) > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting device by ID {}: {}", deviceId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean deleteByUserIdAndDeviceId(String userId, String deviceId) {
        logger.info("JdbcDeviceRepository.deleteByUserIdAndDeviceId called for userId: {}, deviceId: {}", userId, deviceId);
        if (userId == null || deviceId == null) return false;
        String sql = "DELETE FROM devices WHERE user_id = ? AND device_id = ?";
        try {
            return jdbcTemplate.update(sql, userId, deviceId) > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting device by user ID {} and device ID {}: {}", userId, deviceId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateLastActiveAt(String deviceId, Instant lastActiveAt) {
        logger.info("JdbcDeviceRepository.updateLastActiveAt called for deviceId: {}", deviceId);
        if (deviceId == null || lastActiveAt == null) {
            throw new IllegalArgumentException("Device ID and lastActiveAt cannot be null.");
        }
        String sql = "UPDATE devices SET last_active_at = ? WHERE device_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, Timestamp.from(lastActiveAt), deviceId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating last_active_at for device ID {}: {}", deviceId, e.getMessage(), e);
            return false;
        }
    }
}

