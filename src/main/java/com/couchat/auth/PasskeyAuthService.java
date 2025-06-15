package com.couchat.auth;

import com.couchat.device.model.Device;
import com.couchat.repository.DeviceRepository;
import com.couchat.user.model.User;
import com.couchat.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;

/**
 * Manages device passkey authentication and user association.
 * This service will handle identifying the current device and loading associated user information.
 * It will also provide methods for user registration and login, associating devices with users.
 */
@Service
public class PasskeyAuthService {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyAuthService.class);

    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository; // Keep for registration/login logic

    private static final String CONFIG_DIR_NAME = ".couchat";
    private static final String DEVICE_PROPERTIES_FILE_NAME = "device.properties";
    private static final String KEY_DEVICE_ID = "device.id";

    private String localUserId;
    private String currentDeviceId;
    private boolean authenticated = false;

    @Autowired
    public PasskeyAuthService(DeviceRepository deviceRepository, UserRepository userRepository) {
        this.deviceRepository = deviceRepository;
        this.userRepository = userRepository;
    }

    @PostConstruct
    public void init() {
        logger.info("Initializing PasskeyAuthService...");
        this.currentDeviceId = loadLocalDeviceId();

        if (this.currentDeviceId != null) {
            logger.info("Loaded local device ID: {}", this.currentDeviceId);
            Optional<Device> deviceOpt = deviceRepository.findById(this.currentDeviceId);
            if (deviceOpt.isPresent()) {
                Device device = deviceOpt.get();
                this.localUserId = device.getUserId();
                this.authenticated = true; // Mark as authenticated if device and user are found
                logger.info("Device {} successfully authenticated for user ID: {}.", this.currentDeviceId, this.localUserId);
            } else {
                logger.warn("Device ID {} found locally, but no matching device found in the database. Device may need to be re-registered.", this.currentDeviceId);
                // Optionally, clear the local device ID if it's invalid
                // clearLocalDeviceId();
                this.authenticated = false;
            }
        } else {
            logger.info("No local device ID found. Device needs to be registered or user needs to log in to associate this device.");
            this.authenticated = false;
        }
    }

    private Path getDevicePropertiesPath() {
        String userHome = System.getProperty("user.home");
        return Paths.get(userHome, CONFIG_DIR_NAME, DEVICE_PROPERTIES_FILE_NAME);
    }

    private String loadLocalDeviceId() {
        Path propertiesPath = getDevicePropertiesPath();
        if (Files.exists(propertiesPath)) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(propertiesPath.toFile())) {
                props.load(fis);
                String deviceId = props.getProperty(KEY_DEVICE_ID);
                if (deviceId != null && !deviceId.trim().isEmpty()) {
                    return deviceId.trim();
                } else {
                    logger.warn("Device properties file found, but {} is missing or empty.", KEY_DEVICE_ID);
                }
            } catch (IOException e) {
                logger.error("Failed to load device ID from {}: {}", propertiesPath, e.getMessage());
            }
        } else {
            logger.info("Device properties file not found at {}.", propertiesPath);
        }
        return null;
    }

    private void saveLocalDeviceId(String deviceId) {
        Path propertiesPath = getDevicePropertiesPath();
        try {
            Files.createDirectories(propertiesPath.getParent()); // Ensure .couchat directory exists
            Properties props = new Properties();
            props.setProperty(KEY_DEVICE_ID, deviceId);
            try (FileOutputStream fos = new FileOutputStream(propertiesPath.toFile())) {
                props.store(fos, "CouChat Device Configuration");
                logger.info("Saved device ID {} to {}", deviceId, propertiesPath);
            }
        } catch (IOException e) {
            logger.error("Failed to save device ID to {}: {}", propertiesPath, e.getMessage());
        }
    }

    private void clearLocalDeviceId() {
        Path propertiesPath = getDevicePropertiesPath();
        try {
            if (Files.deleteIfExists(propertiesPath)) {
                logger.info("Cleared local device ID file: {}", propertiesPath);
            }
        } catch (IOException e) {
            logger.error("Failed to delete local device ID file {}: {}", propertiesPath, e.getMessage());
        }
    }

    /**
     * Gets the local user ID for the current authenticated session.
     * @return The local user ID, or null if not authenticated.
     */
    public String getLocalUserId() {
        if (!authenticated) {
            logger.warn("Attempted to get localUserId, but not authenticated.");
        }
        return localUserId;
    }

    /**
     * Gets the current device ID for this instance.
     * @return The current device ID, or null if not identified.
     */
    public String getCurrentDeviceId() {
         // currentDeviceId is loaded during init or set during registration/login
        return currentDeviceId;
    }

    /**
     * Checks if the current session is considered authenticated.
     * Authentication means a local device ID is loaded and successfully mapped to a device and user in the database.
     * @return True if authenticated, false otherwise.
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Registers a new user and associates the current device with this new user.
     * If a local device ID already exists, this operation might be disallowed or handled specially.
     *
     * @param username The desired username for the new user.
     * @param deviceName A user-friendly name for the current device.
     * @return An Optional containing the new User if registration was successful, otherwise empty.
     */
    public Optional<User> registerNewUserAndDevice(String username, String deviceName) {
        if (username == null || username.trim().isEmpty()) {
            logger.warn("Registration attempt with empty username.");
            return Optional.empty();
        }
        if (this.authenticated && this.currentDeviceId != null) {
            // This case means a device ID is already loaded and authenticated.
            // Re-registration might mean creating a new user for an already identified device,
            // or it might be an error. For now, let's assume a new user means this device
            // should be associated with that new user, potentially overwriting old association
            // if the UI flow allows it. Or, more simply, disallow if already authenticated.
            logger.warn("Registration attempt on an already authenticated device ({}). Current user: {}. This flow needs clarification.", this.currentDeviceId, this.localUserId);
            // For now, let's prevent re-registration if already authenticated to avoid complexity.
            // A proper flow would involve logging out or explicit re-association.
             return Optional.empty(); // Or throw exception
        }

        if (userRepository.findByUsername(username).isPresent()) {
            logger.warn("Username {} already exists. Cannot register.", username);
            return Optional.empty();
        }

        User newUser = new User(username.trim()); // Constructor generates userId
        // In a real Passkey flow, password_hash might not be used directly.
        // newUser.setPasswordHash(...); // If using passwords
        userRepository.save(newUser);
        logger.info("New user {} registered with ID: {}", newUser.getUsername(), newUser.getUserId());

        Device newDevice = new Device(newUser.getUserId(), deviceName != null ? deviceName : "My Device");
        // In a real Passkey flow, passkey_credential_id etc. would be set here after WebAuthn ceremony
        deviceRepository.save(newDevice);
        logger.info("New device {} registered for user {} with name: {}", newDevice.getDeviceId(), newUser.getUserId(), newDevice.getDeviceName());

        saveLocalDeviceId(newDevice.getDeviceId());

        // Update current service state
        this.localUserId = newUser.getUserId();
        this.currentDeviceId = newDevice.getDeviceId();
        this.authenticated = true;

        return Optional.of(newUser);
    }

    /**
     * Logs in an existing user and associates the current device if not already associated.
     * Placeholder: Uses username for "login". Real Passkey login is a challenge-response flow.
     *
     * @param username The username to log in.
     * @param deviceName A user-friendly name for the current device if it needs to be newly associated.
     * @return An Optional containing the User if login was successful, otherwise empty.
     */
    public Optional<User> loginUserAndAssociateDevice(String username, String deviceName) {
        if (username == null || username.trim().isEmpty()) {
            logger.warn("Login attempt with empty username.");
            return Optional.empty();
        }

        Optional<User> userOpt = userRepository.findByUsername(username.trim());
        if (userOpt.isEmpty()) {
            logger.warn("Login failed: User {} not found.", username);
            return Optional.empty();
        }
        User user = userOpt.get();

        // At this point, user exists. Now, handle device association.
        // If a local device ID was loaded at init and matches this user, we are good.
        if (this.currentDeviceId != null) {
            Optional<Device> existingDeviceOpt = deviceRepository.findById(this.currentDeviceId);
            if (existingDeviceOpt.isPresent()) {
                Device existingDevice = existingDeviceOpt.get();
                if (existingDevice.getUserId().equals(user.getUserId())) {
                    logger.info("User {} logged in. Device {} already associated and loaded.", user.getUsername(), this.currentDeviceId);
                    this.localUserId = user.getUserId(); // Ensure it's set
                    this.authenticated = true;
                    return Optional.of(user);
                } else {
                    // Local device ID exists but belongs to a different user. This is a conflict.
                    // Forcing re-association with the new login.
                    logger.warn("Local device ID {} was associated with user {}, but logging in as user {}. Re-associating device.",
                                this.currentDeviceId, existingDevice.getUserId(), user.getUserId());
                    // Fall through to create new device association for the current user.
                    // The old device ID stored locally will be overwritten.
                }
            }
        }

        // No valid local device ID for this user, or we are re-associating.
        // Create a new device association for this user.
        Device newDevice = new Device(user.getUserId(), deviceName != null ? deviceName : "My Device");
        deviceRepository.save(newDevice);
        logger.info("Associated new device {} for user {} with name: {}", newDevice.getDeviceId(), user.getUserId(), newDevice.getDeviceName());

        saveLocalDeviceId(newDevice.getDeviceId());

        this.localUserId = user.getUserId();
        this.currentDeviceId = newDevice.getDeviceId();
        this.authenticated = true;

        return Optional.of(user);
    }

    /**
     * Logs out the current user by clearing authentication state and local device ID.
     */
    public void logout() {
        logger.info("Logging out user {} from device {}.", this.localUserId, this.currentDeviceId);
        this.localUserId = null;
        // this.currentDeviceId = null; // Keep currentDeviceId loaded from file unless explicitly cleared
        this.authenticated = false;
        clearLocalDeviceId(); // Clear the stored device ID to force re-login/re-registration next time
        this.currentDeviceId = null; // Also clear in-memory
        logger.info("User logged out. Local device ID cleared.");
    }


    // TODO: Implement actual Passkey (WebAuthn) server-side logic for:
    // 1. Registration Challenge Generation (/passkey/register/begin)
    //    - Takes username.
    //    - Generates PublicKeyCredentialCreationOptions.
    //    - Stores challenge temporarily (e.g., in HTTP session or short-lived cache).
    //    - Returns options to client.
    // 2. Registration Verification (/passkey/register/finish)
    //    - Takes client's response (PublicKeyCredential).
    //    - Verifies signature, challenge, origin, etc.
    //    - If valid, creates User (if new), creates Device (stores credentialId, publicKey, signCount).
    //    - Saves local device ID. Sets authenticated state.
    // 3. Authentication Challenge Generation (/passkey/login/begin)
    //    - Optionally takes username, or allows discovery by credentialId.
    //    - Generates PublicKeyCredentialRequestOptions (allows specific credential IDs for this user).
    //    - Stores challenge.
    //    - Returns options to client.
    // 4. Authentication Verification (/passkey/login/finish)
    //    - Takes client's response.
    //    - Verifies signature, challenge, sign count.
    //    - If valid, loads User and Device.
    //    - Saves local device ID. Sets authenticated state.
}
