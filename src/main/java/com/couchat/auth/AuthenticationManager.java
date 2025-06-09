package com.couchat.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Manages user authentication, including username/password, OAuth 2.0 (simulated),
 * and device passkey binding.
 * Interacts with an SQLite database to store user and device information.
 */
public class AuthenticationManager implements AuthenticationInterface {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationManager.class);
    private static final String DB_URL = "jdbc:sqlite:couchat_storage.db";

    // In-memory store for logged-in user sessions (username -> isLoggedIn)
    // For a real application, this should be replaced with a more robust session management mechanism.
    private final Map<String, Boolean> loggedInUsers = new HashMap<>();

    /**
     * Constructs an AuthenticationManager and initializes the database tables if they don't exist.
     * Also ensures a default test user is present for testing purposes.
     */
    public AuthenticationManager() {
        initializeDatabaseTables();
        addUserToDbIfNotExists("testuser", "password123");
    }

    /**
     * Initializes the necessary database tables (users, devices) if they do not already exist.
     * This method defines the schema for user accounts and their associated devices.
     */
    private void initializeDatabaseTables() {
        String createUserTableSql = "CREATE TABLE IF NOT EXISTS users (" +
                "user_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username TEXT UNIQUE NOT NULL, " +
                "password_hash TEXT, " +
                "oauth_provider TEXT, " +
                "oauth_id TEXT, " +
                "UNIQUE (oauth_provider, oauth_id)" +
                ")";

        String createDeviceTableSql = "CREATE TABLE IF NOT EXISTS devices (" +
                "device_id TEXT PRIMARY KEY, " +
                "user_id INTEGER NOT NULL, " +
                "passkey_hash TEXT, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "FOREIGN KEY (user_id) REFERENCES users(user_id)" +
                ")";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(createUserTableSql);
            logger.info("Ensured 'users' table exists.");
            stmt.execute(createDeviceTableSql);
            logger.info("Ensured 'devices' table exists.");
        } catch (SQLException e) {
            logger.error("Error initializing database tables", e);
            // Consider re-throwing as a runtime exception if the application cannot proceed
            // throw new RuntimeException("Failed to initialize database tables", e);
        }
    }

    /**
     * Adds a new user to the database if they do not already exist.
     * Primarily used for setting up default users or test accounts.
     *
     * @param username The username of the user to add.
     * @param password The plain-text password for the user (will be hashed before storage).
     */
    private void addUserToDbIfNotExists(String username, String password) {
        if (username == null || username.trim().isEmpty() ||
            password == null || password.trim().isEmpty()) {
            logger.warn("Cannot add user: username or password is null or empty");
            return;
        }

        String checkSql = "SELECT user_id FROM users WHERE username = ?";
        String insertSql = "INSERT INTO users (username, password_hash) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {

            checkStmt.setString(1, username);
            try (ResultSet rs = checkStmt.executeQuery()) {
                if (!rs.next()) { // User does not exist, proceed to add
                    try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                        insertStmt.setString(1, username);
                        insertStmt.setString(2, hashPassword(password));
                        int affectedRows = insertStmt.executeUpdate();
                        if (affectedRows > 0) {
                            logger.info("Added new user: {}", username);
                        } else {
                            logger.warn("Failed to add new user: {} (no rows affected)", username);
                        }
                    }
                } else {
                    logger.debug("User '{}' already exists. Skipping addition.", username);
                }
            }
        } catch (SQLException e) {
            logger.error("Error adding user '{}' to database", username, e);
        }
    }

    /**
     * Hashes a given password using SHA-256.
     *
     * @param password The plain-text password to hash.
     * @return The Base64 encoded string of the hashed password, or null if hashing fails.
     */
    String hashPassword(String password) {
        if (password == null) return null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error hashing password: SHA-256 algorithm not found.", e);
            return null; // Or throw a runtime exception
        }
    }

    /**
     * Authenticates a user based on their username and password.
     * Compares the hash of the provided password with the stored hash.
     *
     * @param username The username.
     * @param password The password.
     */
    @Override
    public void authenticateUser(String username, String password) {
        logger.debug("Attempting to authenticate user: {}", username);
        if (username == null || username.trim().isEmpty() ||
            password == null || password.trim().isEmpty()) {
            logger.warn("Authentication failed for user '{}': username or password is null or empty.", username);
            return;
        }

        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String storedHash = rs.getString("password_hash");
                    String inputHash = hashPassword(password);
                    if (storedHash != null && storedHash.equals(inputHash)) {
                        loggedInUsers.put(username, true);
                        logger.info("User '{}' authenticated successfully via password.", username);
                        return;
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Database error during password authentication for user: {}", username, e);
        }
        logger.warn("Authentication failed for user: {} (password mismatch or user not found).", username);
    }

    /**
     * Authenticates a user using a simulated OAuth token.
     * For prototype purposes, the token is expected to be in the format "PROVIDER:ID".
     * If the user doesn't exist, a new user account is created based on the OAuth information.
     *
     * @param oauthToken A simulated OAuth token, e.g., "GOOGLE:user12345" or "MICROSOFT:abcdef".
     */
    @Override
    public void authenticateWithOAuth(String oauthToken) {
        logger.debug("Attempting to authenticate with OAuth token (first 15 chars): {}",
            (oauthToken != null && oauthToken.length() > 15) ? oauthToken.substring(0, 15) + "..." : oauthToken);

        if (oauthToken == null || oauthToken.trim().isEmpty()) {
            logger.warn("OAuth authentication failed: token is null or empty.");
            return;
        }

        String[] parts = oauthToken.split(":", 2);
        if (parts.length != 2) {
            logger.warn("OAuth authentication failed: token format is invalid. Expected 'PROVIDER:ID'. Token: {}", oauthToken);
            return;
        }

        String provider = parts[0].toUpperCase(); // Normalize provider name
        String oauthId = parts[1];

        if (provider.isEmpty() || oauthId.isEmpty()) {
            logger.warn("OAuth authentication failed: provider or ID is empty in token. Token: {}", oauthToken);
            return;
        }

        String findUserSql = "SELECT user_id, username FROM users WHERE oauth_provider = ? AND oauth_id = ?";
        String insertUserSql = "INSERT INTO users (username, oauth_provider, oauth_id) VALUES (?, ?, ?)";
        String generatedUsername = provider.toLowerCase() + "_" + oauthId; // e.g., google_user12345

        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            try (PreparedStatement findStmt = conn.prepareStatement(findUserSql)) {
                findStmt.setString(1, provider);
                findStmt.setString(2, oauthId);
                try (ResultSet rs = findStmt.executeQuery()) {
                    if (rs.next()) { // User found
                        String existingUsername = rs.getString("username");
                        loggedInUsers.put(existingUsername, true);
                        logger.info("User '{}' (OAuth ID: {}) authenticated successfully via {} OAuth.", existingUsername, oauthId, provider);
                    } else { // User not found, create new user
                        logger.info("OAuth user {} from {} not found. Creating new user: {}", oauthId, provider, generatedUsername);
                        try (PreparedStatement insertStmt = conn.prepareStatement(insertUserSql, Statement.RETURN_GENERATED_KEYS)) {
                            insertStmt.setString(1, generatedUsername);
                            insertStmt.setString(2, provider);
                            insertStmt.setString(3, oauthId);
                            int affectedRows = insertStmt.executeUpdate();
                            if (affectedRows > 0) {
                                // Optional: retrieve generated user_id if needed
                                // try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) { ... }
                                loggedInUsers.put(generatedUsername, true);
                                logger.info("New user '{}' created and authenticated via {} OAuth (ID: {}).", generatedUsername, provider, oauthId);
                            } else {
                                logger.error("Failed to create new OAuth user '{}' (ID: {} from {}). No rows affected.", generatedUsername, oauthId, provider);
                            }
                        }
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Database error during OAuth authentication for provider '{}', ID '{}'", provider, oauthId, e);
        }
    }

    /**
     * Binds a device passkey to the currently logged-in user.
     * The passkey is hashed before being stored.
     *
     * @param deviceId The unique identifier for the device.
     * @param passkey  The passkey string to bind (will be hashed).
     */
    @Override
    public void bindDevicePasskey(String deviceId, String passkey) {
        logger.debug("Attempting to bind device passkey for device: {}", deviceId);
        if (deviceId == null || deviceId.trim().isEmpty() ||
            passkey == null || passkey.trim().isEmpty()) {
            logger.warn("Cannot bind device passkey: deviceId or passkey is null or empty.");
            return;
        }

        Optional<String> loggedInUsernameOpt = getFirstLoggedInUsername();
        if (loggedInUsernameOpt.isEmpty()) {
            logger.warn("Cannot bind device passkey for device '{}': No user is currently logged in.", deviceId);
            return;
        }
        String loggedInUsername = loggedInUsernameOpt.get();

        Optional<Integer> userIdOpt = getUserIdByUsername(loggedInUsername);
        if (userIdOpt.isEmpty()) {
            logger.warn("Cannot bind device passkey for device '{}': Logged in user '{}' not found in database.", deviceId, loggedInUsername);
            return;
        }
        int userId = userIdOpt.get();

        String passkeyHash = hashPassword(passkey);
        if (passkeyHash == null) {
            logger.error("Cannot bind device passkey for device '{}': Passkey hashing failed.", deviceId);
            return;
        }

        String upsertSql = "INSERT INTO devices (device_id, user_id, passkey_hash) VALUES (?, ?, ?) " +
                           "ON CONFLICT(device_id) DO UPDATE SET user_id = excluded.user_id, passkey_hash = excluded.passkey_hash";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(upsertSql)) {
            stmt.setString(1, deviceId);
            stmt.setInt(2, userId);
            stmt.setString(3, passkeyHash);
            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                 logger.info("Successfully bound/updated passkey for device '{}' to user '{}' (ID: {}).", deviceId, loggedInUsername, userId);
            } else {
                // This case might not be reached with ON CONFLICT DO UPDATE if the device_id exists,
                // as it would update. If it doesn't exist, it inserts.
                // A 0 affectedRows might indicate an issue if the insert/update was expected but didn't happen.
                logger.warn("Binding/updating passkey for device '{}' resulted in 0 affected rows. Check DB state or SQL logic.", deviceId);
            }
        } catch (SQLException e) {
            logger.error("Database error binding device passkey for device: {}", deviceId, e);
        }
    }

    /**
     * Retrieves the first username found in the in-memory logged-in users map.
     * This is a simplistic approach for prototype purposes.
     *
     * @return An {@link Optional} containing the username if a user is logged in, otherwise empty.
     */
    private Optional<String> getFirstLoggedInUsername() {
        return loggedInUsers.entrySet().stream()
                .filter(Map.Entry::getValue) // Filter for true (logged in)
                .map(Map.Entry::getKey)
                .findFirst();
    }

    /**
     * Retrieves the passkey hash for a given device ID.
     *
     * @param deviceId The unique identifier of the device.
     * @return The stored passkey hash as a String, or null if the device is not found or has no passkey.
     */
    public String getBoundPasskeyHash(String deviceId) {
        if (deviceId == null || deviceId.trim().isEmpty()) {
            logger.debug("Cannot get passkey hash: deviceId is null or empty.");
            return null;
        }
        String sql = "SELECT passkey_hash FROM devices WHERE device_id = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, deviceId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("passkey_hash");
                }
            }
        } catch (SQLException e) {
            logger.error("Database error getting passkey hash for device: {}", deviceId, e);
        }
        logger.debug("No passkey hash found for device: {}", deviceId);
        return null;
    }

    /**
     * Checks if a user is currently marked as logged in (in-memory).
     *
     * @param username The username to check.
     * @return true if the user is logged in, false otherwise.
     */
    public boolean isUserLoggedIn(String username) {
        if (username == null) return false;
        return loggedInUsers.getOrDefault(username, false);
    }

    /**
     * Clears all authentication-related data, including in-memory logged-in users
     * and database records in 'users' and 'devices' tables.
     * Primarily intended for test environment cleanup.
     * Re-adds the default test user after clearing.
     */
    public void clearAllAuthentications() {
        logger.info("Clearing all authentication data (in-memory and DB)... ");
        loggedInUsers.clear();
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM devices");
            stmt.execute("DELETE FROM users");
            // Reset autoincrement sequence for 'users' table if it exists and is supported by SQLite version
            // stmt.execute("DELETE FROM sqlite_sequence WHERE name='users'"); // This might fail if table was just created or empty
            logger.info("Cleared 'devices' and 'users' tables in the database.");
        } catch (SQLException e) {
            logger.error("Error clearing authentication DB tables", e);
        }
        // Re-add the default test user so it's available for subsequent tests.
        addUserToDbIfNotExists("testuser", "password123");
        logger.info("Default test user 'testuser' re-added after clearing authentications.");
    }

    /**
     * Retrieves the user_id for a given username from the database.
     *
     * @param username The username to search for.
     * @return An {@link Optional} containing the user_id if found, otherwise empty.
     */
    private Optional<Integer> getUserIdByUsername(String username) {
        if (username == null || username.trim().isEmpty()) return Optional.empty();
        String sql = "SELECT user_id FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(rs.getInt("user_id"));
                }
            }
        } catch (SQLException e) {
            logger.error("Database error retrieving user_id for username: {}", username, e);
        }
        return Optional.empty();
    }
}
