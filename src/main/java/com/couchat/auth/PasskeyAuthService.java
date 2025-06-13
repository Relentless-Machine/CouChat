package com.couchat.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import java.util.UUID;

/**
 * Manages device passkey authentication.
 * On first run, generates a unique user ID (peer ID) and a device passkey.
 * These are stored in a properties file in the user's home directory.
 * Subsequent runs load these credentials.
 */
@Service
public class PasskeyAuthService {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyAuthService.class);

    private static final String CONFIG_DIR_NAME = ".couchat";
    private static final String PROPERTIES_FILE_NAME = "user.properties";
    private static final String KEY_USER_ID = "user.id";
    private static final String KEY_DEVICE_PASSKEY = "device.passkey";

    private String localPeerId;
    private String devicePasskey;
    private boolean authenticated = false;

    @PostConstruct
    public void init() {
        File configDir = new File(System.getProperty("user.home"), CONFIG_DIR_NAME);
        File configFile = new File(configDir, PROPERTIES_FILE_NAME);

        Properties properties = new Properties();

        if (configFile.exists() && configFile.isFile()) {
            try (InputStream input = new FileInputStream(configFile)) {
                properties.load(input);
                this.localPeerId = properties.getProperty(KEY_USER_ID);
                this.devicePasskey = properties.getProperty(KEY_DEVICE_PASSKEY);

                if (this.localPeerId != null && !this.localPeerId.isEmpty() &&
                    this.devicePasskey != null && !this.devicePasskey.isEmpty()) {
                    this.authenticated = true;
                    logger.info("User properties loaded successfully. Peer ID: {}", this.localPeerId);
                } else {
                    logger.warn("User properties file found, but content is invalid. Regenerating credentials.");
                    generateAndStoreCredentials(configFile, properties);
                }
            } catch (IOException e) {
                logger.error("Failed to load user properties from {}. Regenerating credentials.", configFile.getAbsolutePath(), e);
                generateAndStoreCredentials(configFile, properties);
            }
        } else {
            logger.info("User properties file not found at {}. Generating new credentials.", configFile.getAbsolutePath());
            if (!configDir.exists()) {
                if (configDir.mkdirs()) {
                    logger.info("Created configuration directory: {}", configDir.getAbsolutePath());
                } else {
                    logger.error("Failed to create configuration directory: {}. Credentials will not be persisted.", configDir.getAbsolutePath());
                    // Fallback: generate in-memory for current session if directory creation fails
                    generateInMemoryCredentials();
                    return;
                }
            }
            generateAndStoreCredentials(configFile, properties);
        }
    }

    private void generateAndStoreCredentials(File configFile, Properties properties) {
        this.localPeerId = UUID.randomUUID().toString();
        this.devicePasskey = generateSecurePasskey();
        this.authenticated = true;

        properties.setProperty(KEY_USER_ID, this.localPeerId);
        properties.setProperty(KEY_DEVICE_PASSKEY, this.devicePasskey);

        try (OutputStream output = new FileOutputStream(configFile)) {
            properties.store(output, "CouChat User Properties");
            logger.info("New user credentials generated and stored successfully. Peer ID: {}", this.localPeerId);
        } catch (IOException e) {
            logger.error("Failed to store user properties to {}. Credentials will be in-memory for this session.", configFile.getAbsolutePath(), e);
            // If storing fails, we still have them in memory for the current session.
        }
    }

    private void generateInMemoryCredentials() {
        this.localPeerId = UUID.randomUUID().toString();
        this.devicePasskey = generateSecurePasskey();
        this.authenticated = true;
        logger.warn("Using in-memory credentials for this session as directory creation/writing failed.");
    }

    private String generateSecurePasskey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32]; // 256 bits
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Gets the local peer ID for this user/installation.
     * This ID is used for P2P communication.
     *
     * @return The local peer ID, or null if authentication failed.
     */
    public String getLocalPeerId() {
        return localPeerId;
    }

    /**
     * Gets the device passkey.
     * This passkey can be used to protect local sensitive data, such as cryptographic keys.
     *
     * @return The device passkey, or null if authentication failed.
     */
    public String getDevicePasskey() {
        return devicePasskey;
    }

    /**
     * Checks if the user/device has been authenticated (i.e., credentials loaded or generated).
     *
     * @return True if authenticated, false otherwise.
     */
    public boolean isAuthenticated() {
        return authenticated;
    }
}

