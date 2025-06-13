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
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List; // Added import
import java.util.Optional;
import java.util.UUID;

// TODO: This class needs significant refactoring to align with the new database schema
// and a proper Passkey (WebAuthn) flow. The current file-based storage is a placeholder.

/**
 * Manages device passkey authentication and user association.
 * Placeholder: Current implementation uses local file storage for a single user/device concept.
 * This needs to be refactored to use the database (DeviceRepository, UserRepository)
 * and integrate with a proper Passkey (WebAuthn server-side) flow.
 */
@Service
public class PasskeyAuthService {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyAuthService.class);

    // Dependencies for database interaction (to be used in refactored version)
    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;

    // Old file-based properties (to be deprecated/removed)
    // private static final String CONFIG_DIR_NAME = ".couchat";
    // private static final String PROPERTIES_FILE_NAME = "user.properties";
    // private static final String KEY_USER_ID = "user.id";
    // private static final String KEY_DEVICE_PASSKEY = "device.passkey";

    private String localUserId; // Represents the currently "logged-in" user for this device instance
    private String currentDeviceId; // Represents this specific device instance
    private boolean authenticated = false;

    @Autowired
    public PasskeyAuthService(DeviceRepository deviceRepository, UserRepository userRepository) {
        this.deviceRepository = deviceRepository;
        this.userRepository = userRepository;
    }

    @PostConstruct
    public void init() {
        // TODO: Refactor init() to:
        // 1. Check if a device_id is stored locally (e.g., in a secure properties file or OS secure storage).
        // 2. If found, try to load the device from DeviceRepository.
        // 3. If not found, or if this is a "new registration" flow, guide user through user creation/login
        //    and then device registration (Passkey creation).
        // The old file-based logic is commented out as it's not compatible with multi-user/multi-device.
        logger.warn("PasskeyAuthService.init() needs complete refactoring for database and proper Passkey flow.");
        // For now, let's simulate a default user/device for demo if nothing else is set up.
        // This is a placeholder for development and should not be used in production.
        // initializeOrRegisterPlaceholderDevice(); // Called by isAuthenticated or getLocalUserId if needed
    }

    // Placeholder for a simplified device registration / retrieval for demo purposes
    // This would be replaced by actual Passkey registration and login flows.
    private void initializeOrRegisterPlaceholderDevice() {
        if (this.authenticated) return; // Already initialized

        logger.info("Attempting to initialize placeholder device and user...");
        // Try to find a "default" user or create one
        Optional<User> userOpt = userRepository.findByUsername("defaultUser");
        User user;
        if (userOpt.isEmpty()) {
            user = new User("defaultUser"); // Uses constructor that generates UUID for userId
            // user.setPasswordHash(generateSecurePasskey()); // Simulate a password/passkey - not strictly needed for this placeholder
            userRepository.save(user);
            logger.info("Created placeholder user: {} with ID: {}", user.getUsername(), user.getUserId());
        }
        else {
            user = userOpt.get();
            logger.info("Found existing placeholder user: {} with ID: {}", user.getUsername(), user.getUserId());
        }
        this.localUserId = user.getUserId();

        // Try to find a device for this user or create one
        List<Device> devices = deviceRepository.findByUserId(this.localUserId);
        Device device;
        if (devices.isEmpty()) {
            device = new Device(this.localUserId, "Default Device"); // Uses constructor that generates UUID for deviceId
            // Simulate a passkey credential ID being stored
            // device.setPasskeyCredentialId(Base64.getUrlEncoder().encodeToString(UUID.randomUUID().toString().getBytes()));
            deviceRepository.save(device);
            logger.info("Created placeholder device: {} for user {}", device.getDeviceId(), this.localUserId);
        }
        else {
            device = devices.get(0); // Just take the first one for this placeholder
            logger.info("Found existing placeholder device: {} for user {}", device.getDeviceId(), this.localUserId);
        }
        this.currentDeviceId = device.getDeviceId();
        this.authenticated = true;
        logger.info("Placeholder authentication complete. UserID: {}, DeviceID: {}", this.localUserId, this.currentDeviceId);
    }


    private String generateSecurePasskey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32]; // 256 bits
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Gets the local user ID for the current authenticated session.
     * TODO: This needs to be tied to an actual login session.
     *
     * @return The local user ID, or null if not authenticated (after trying placeholder init).
     */
    public String getLocalUserId() {
        if (!authenticated) {
            logger.warn("Attempted to get localUserId, but not authenticated. Triggering placeholder init.");
            initializeOrRegisterPlaceholderDevice();
        }
        return localUserId;
    }

    /**
     * Gets the current device ID for this instance.
     * TODO: This needs to be tied to an actual device registration and session.
     *
     * @return The current device ID, or null if not identified (after trying placeholder init).
     */
    public String getCurrentDeviceId() {
         if (!authenticated) {
            logger.warn("Attempted to get currentDeviceId, but not authenticated. Triggering placeholder init.");
            initializeOrRegisterPlaceholderDevice();
        }
        return currentDeviceId;
    }

    /**
     * Checks if the current session is considered authenticated.
     * TODO: This needs to be based on a proper authentication flow.
     *
     * @return True if authenticated, false otherwise.
     */
    public boolean isAuthenticated() {
        if (!authenticated) {
             // logger.info("isAuthenticated() called: Not authenticated, attempting placeholder initialization.");
             // initializeOrRegisterPlaceholderDevice(); // Let getLocalUserId or getCurrentDeviceId trigger this if needed.
        }
        return authenticated;
    }

    // TODO: Add methods for Passkey registration (begin, finish)
    // public RegistrationResponse beginRegistration(String username) { ... }
    // public boolean finishRegistration(String username, String registrationJson) { ... }

    // TODO: Add methods for Passkey authentication (begin, finish)
    // public AuthenticationResponse beginAuthentication(String username) { ... }
    // public boolean finishAuthentication(String username, String authenticationJson) { ... }
}
