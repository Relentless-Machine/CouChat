package com.couchat.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link AuthenticationManager} class.
 * These tests cover username/password authentication, simulated OAuth 2.0 authentication,
 * device passkey binding, and interaction with the SQLite database.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticationManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationManagerTest.class);
    private AuthenticationManager authenticationManager;
    private static final String DB_URL = "jdbc:sqlite:couchat_storage.db";

    /**
     * Sets up the testing environment before each test.
     * Initializes a new {@link AuthenticationManager} instance and clears any
     * existing authentication data to ensure a clean state for each test.
     */
    @BeforeEach
    void setUp() {
        authenticationManager = new AuthenticationManager();
        // Clear all users and devices from the database and in-memory loggedInUsers map.
        // This also re-adds the default 'testuser'.
        authenticationManager.clearAllAuthentications();
        logger.info("AuthenticationManager initialized and all authentication data cleared for test.");
    }

    /**
     * Cleans up the testing environment after each test.
     * Currently, this method doesn't perform additional cleanup beyond what setUp does,
     * but it's good practice to have for future needs.
     */
    @AfterEach
    void tearDown() {
        // authenticationManager.clearAllAuthentications(); // Optionally clear again after test
        logger.info("Test finished.");
    }

    // --- Username/Password Authentication Tests ---

    /**
     * Tests successful user authentication with a correct username and password.
     */
    @Test
    void testAuthenticateUser_Success() {
        logger.info("Testing successful user authentication for 'testuser'.");
        authenticationManager.authenticateUser("testuser", "password123");
        assertTrue(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should be logged in after successful password authentication.");
    }

    /**
     * Tests failed user authentication due to an incorrect password.
     */
    @Test
    void testAuthenticateUser_Failure_WrongPassword() {
        logger.info("Testing failed user authentication for 'testuser' due to wrong password.");
        authenticationManager.authenticateUser("testuser", "wrongpassword");
        assertFalse(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should not be logged in with an incorrect password.");
    }

    /**
     * Tests failed user authentication for a username that does not exist in the database.
     */
    @Test
    void testAuthenticateUser_Failure_UnknownUser() {
        logger.info("Testing failed user authentication for an unknown user 'unknownuser'.");
        authenticationManager.authenticateUser("unknownuser", "password123");
        assertFalse(authenticationManager.isUserLoggedIn("unknownuser"),
                "Unknown user 'unknownuser' should not be logged in.");
    }

    /**
     * Tests user authentication attempt with a null username.
     * Expects authentication to fail gracefully.
     */
    @Test
    void testAuthenticateUser_NullUsername() {
        logger.info("Testing user authentication with null username.");
        authenticationManager.authenticateUser(null, "password123");
        assertFalse(authenticationManager.isUserLoggedIn(null), // Check against null explicitly
                "Authentication should fail, and no user should be logged in with a null username.");
    }

    /**
     * Tests user authentication attempt with an empty password.
     * Expects authentication to fail.
     */
    @Test
    void testAuthenticateUser_EmptyPassword() {
        logger.info("Testing user authentication for 'testuser' with an empty password.");
        authenticationManager.authenticateUser("testuser", "");
        assertFalse(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should not be logged in with an empty password.");
    }

    // --- OAuth 2.0 Authentication Tests (Simulated) ---

    /**
     * Tests successful OAuth authentication for a new user.
     * Expects a new user to be created in the database and logged in.
     */
    @Test
    void testAuthenticateWithOAuth_NewUser_Success() {
        String oauthToken = "GOOGLE:newoauthuser123";
        String expectedUsername = "google_newoauthuser123";
        logger.info("Testing successful OAuth authentication for a new user with token: {}", oauthToken);

        authenticationManager.authenticateWithOAuth(oauthToken);
        assertTrue(authenticationManager.isUserLoggedIn(expectedUsername),
                "User '" + expectedUsername + "' should be logged in after successful OAuth authentication for a new user.");

        // Verify user was created in the database with OAuth details
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement("SELECT oauth_provider, oauth_id FROM users WHERE username = ?")) {
            stmt.setString(1, expectedUsername);
            try (ResultSet rs = stmt.executeQuery()) {
                assertTrue(rs.next(), "User '" + expectedUsername + "' should exist in the database.");
                assertEquals("GOOGLE", rs.getString("oauth_provider"), "OAuth provider should be GOOGLE.");
                assertEquals("newoauthuser123", rs.getString("oauth_id"), "OAuth ID should be 'newoauthuser123'.");
            }
        } catch (SQLException e) {
            fail("Database error during OAuth new user verification: " + e.getMessage());
        }
    }

    /**
     * Tests successful OAuth authentication for an existing user.
     * Expects the existing user to be identified and logged in.
     */
    @Test
    void testAuthenticateWithOAuth_ExistingUser_Success() {
        String oauthToken = "MICROSOFT:existingoauthuser456";
        String username = "microsoft_existingoauthuser456";

        // Manually add the OAuth user first to simulate an existing user
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO users (username, oauth_provider, oauth_id) VALUES (?, ?, ?)")) {
            stmt.setString(1, username);
            stmt.setString(2, "MICROSOFT");
            stmt.setString(3, "existingoauthuser456");
            stmt.executeUpdate();
            logger.info("Manually inserted existing OAuth user '{}' for test.", username);
        } catch (SQLException e) {
            fail("Failed to pre-insert existing OAuth user for test: " + e.getMessage());
        }

        logger.info("Testing successful OAuth authentication for an existing user with token: {}", oauthToken);
        authenticationManager.authenticateWithOAuth(oauthToken);
        assertTrue(authenticationManager.isUserLoggedIn(username),
                "User '" + username + "' should be logged in after successful OAuth authentication for an existing user.");
    }

    /**
     * Tests failed OAuth authentication due to an invalid token format (missing colon).
     */
    @Test
    void testAuthenticateWithOAuth_Failure_InvalidTokenFormat_NoColon() {
        String invalidToken = "GOOGLE.invalidtoken"; // Invalid format
        logger.info("Testing failed OAuth authentication with invalid token format (no colon): {}", invalidToken);
        authenticationManager.authenticateWithOAuth(invalidToken);
        // No specific user is expected to be logged in from this malformed token.
        // We can check if any unexpected user got logged in, or simply that the intended user (if one could be inferred) is not.
        // For this test, it's sufficient that no error occurs and no one is logged in based on this token.
        assertFalse(authenticationManager.isUserLoggedIn("google_invalidtoken"), "No user should be logged in with a malformed OAuth token.");
    }

    /**
     * Tests failed OAuth authentication due to an invalid token format (empty provider).
     */
    @Test
    void testAuthenticateWithOAuth_Failure_InvalidTokenFormat_EmptyProvider() {
        String invalidToken = ":emptyproviderid";
        logger.info("Testing failed OAuth authentication with invalid token format (empty provider): {}", invalidToken);
        authenticationManager.authenticateWithOAuth(invalidToken);
        assertFalse(authenticationManager.isUserLoggedIn("_emptyproviderid"), "No user should be logged in with an OAuth token with empty provider.");
    }

    /**
     * Tests failed OAuth authentication due to an invalid token format (empty ID).
     */
    @Test
    void testAuthenticateWithOAuth_Failure_InvalidTokenFormat_EmptyId() {
        String invalidToken = "GOOGLE:";
        logger.info("Testing failed OAuth authentication with invalid token format (empty ID): {}", invalidToken);
        authenticationManager.authenticateWithOAuth(invalidToken);
        assertFalse(authenticationManager.isUserLoggedIn("google_"), "No user should be logged in with an OAuth token with empty ID.");
    }


    /**
     * Tests OAuth authentication attempt with a null token.
     * Expects authentication to fail gracefully.
     */
    @Test
    void testAuthenticateWithOAuth_NullToken() {
        logger.info("Testing OAuth authentication with null token.");
        authenticationManager.authenticateWithOAuth(null);
        // Check against a generic potential username or just ensure no unexpected logins
        assertFalse(authenticationManager.isUserLoggedIn("any_oauth_user"),
                "No user should be logged in with a null OAuth token.");
    }

    // --- Device Passkey Binding Tests ---

    /**
     * Tests successful binding of a device passkey to a logged-in user.
     */
    @Test
    void testBindDevicePasskey_Success_UserLoggedIn() {
        String deviceId = "testDevice123";
        String passkey = "strongPasskey456";
        String username = "testuser"; // Default user, should exist

        // Ensure the user is logged in before binding a passkey
        authenticationManager.authenticateUser(username, "password123");
        assertTrue(authenticationManager.isUserLoggedIn(username),
                "User '" + username + "' must be logged in before binding a device passkey.");

        logger.info("Testing successful device passkey binding for device: {}, passkey: {}", deviceId, passkey);
        authenticationManager.bindDevicePasskey(deviceId, passkey);

        String expectedPasskeyHash = authenticationManager.hashPassword(passkey);
        assertEquals(expectedPasskeyHash, authenticationManager.getBoundPasskeyHash(deviceId),
                "Passkey hash should be correctly stored for the device after binding.");
    }

    /**
     * Tests successful update of a device passkey for an existing device.
     */
    @Test
    void testBindDevicePasskey_UpdateExistingDevice_Success() {
        String deviceId = "testDevice789";
        String initialPasskey = "initialPasskey";
        String updatedPasskey = "updatedPasskeyStronger";
        String username = "testuser";

        authenticationManager.authenticateUser(username, "password123");
        assertTrue(authenticationManager.isUserLoggedIn(username));

        // Bind initial passkey
        authenticationManager.bindDevicePasskey(deviceId, initialPasskey);
        String initialHash = authenticationManager.hashPassword(initialPasskey);
        assertEquals(initialHash, authenticationManager.getBoundPasskeyHash(deviceId), "Initial passkey hash should be stored.");

        // Bind updated passkey
        logger.info("Testing update of device passkey for device: {}", deviceId);
        authenticationManager.bindDevicePasskey(deviceId, updatedPasskey);
        String updatedHash = authenticationManager.hashPassword(updatedPasskey);
        assertEquals(updatedHash, authenticationManager.getBoundPasskeyHash(deviceId),
                "Passkey hash should be updated for the existing device.");
        assertNotEquals(initialHash, updatedHash, "Updated hash should be different from the initial hash.");
    }


    /**
     * Tests device passkey binding attempt when no user is logged in.
     * Expects binding to fail.
     */
    @Test
    void testBindDevicePasskey_Failure_NoUserLoggedIn() {
        String deviceId = "testDeviceNoUser";
        String passkey = "passkeyNoUser";
        logger.info("Testing device passkey binding when no user is logged in for device: {}", deviceId);

        // Ensure no user is logged in (setUp clears logins, but double-check)
        assertFalse(authenticationManager.isUserLoggedIn("testuser"), "No user should be logged in for this test scenario.");

        authenticationManager.bindDevicePasskey(deviceId, passkey);
        assertNull(authenticationManager.getBoundPasskeyHash(deviceId),
                "Device passkey should not be bound if no user is logged in.");
    }

    /**
     * Tests device passkey binding attempt with a null device ID.
     * Expects binding to fail gracefully.
     */
    @Test
    void testBindDevicePasskey_NullDeviceId() {
        String username = "testuser";
        authenticationManager.authenticateUser(username, "password123"); // Log in a user
        assertTrue(authenticationManager.isUserLoggedIn(username));

        logger.info("Testing device passkey binding with null device ID.");
        authenticationManager.bindDevicePasskey(null, "strongPasskey789");
        // No specific assertion on stored value for null key, but ensure no error and no unintended binding.
        // For example, check that a lookup for a valid deviceId doesn't return this passkey.
        assertNull(authenticationManager.getBoundPasskeyHash(null), "Passkey hash should be null for a null deviceId query.");
    }

    /**
     * Tests device passkey binding attempt with an empty passkey string.
     * Expects binding to fail.
     */
    @Test
    void testBindDevicePasskey_EmptyPasskey() {
        String deviceId = "testDeviceEmptyPasskey";
        String username = "testuser";
        authenticationManager.authenticateUser(username, "password123"); // Log in a user
        assertTrue(authenticationManager.isUserLoggedIn(username));

        logger.info("Testing device passkey binding with empty passkey for device: {}", deviceId);
        authenticationManager.bindDevicePasskey(deviceId, ""); // Empty passkey
        assertNull(authenticationManager.getBoundPasskeyHash(deviceId),
                "Device passkey should not be bound if the passkey string is empty.");
    }

    // --- Helper and State Verification Tests ---

    /**
     * Tests {@link AuthenticationManager#isUserLoggedIn(String)} for a user that is not logged in.
     */
    @Test
    void testIsUserLoggedIn_False_UnknownOrNotLoggedInUser() {
        logger.info("Testing isUserLoggedIn for a non-existent or not-logged-in user.");
        assertFalse(authenticationManager.isUserLoggedIn("nonexistentuser"),
                "A user not explicitly logged in or unknown should return false for isUserLoggedIn.");
    }

    /**
     * Tests {@link AuthenticationManager#isUserLoggedIn(String)} after a failed login attempt.
     */
    @Test
    void testIsUserLoggedIn_False_AfterFailedLoginAttempt() {
        logger.info("Testing isUserLoggedIn for 'testuser' after a failed login attempt.");
        authenticationManager.authenticateUser("testuser", "incorrectPassword"); // Failed attempt
        assertFalse(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should not be marked as logged in after a failed login attempt.");
    }

    /**
     * Tests the {@link AuthenticationManager#hashPassword(String)} method.
     * Ensures it produces a non-null, non-empty hash for a valid password
     * and that different passwords produce different hashes.
     */
    @Test
    void testHashPassword() {
        logger.info("Testing password hashing utility.");
        String pass1 = "password123";
        String pass2 = "Password123"; // Different password

        String hash1 = authenticationManager.hashPassword(pass1);
        String hash2 = authenticationManager.hashPassword(pass2);
        String hash1Again = authenticationManager.hashPassword(pass1);

        assertNotNull(hash1, "Hash for a valid password should not be null.");
        assertFalse(hash1.isEmpty(), "Hash for a valid password should not be empty.");

        assertEquals(hash1, hash1Again, "Hashing the same password multiple times should produce the same hash.");
        assertNotEquals(hash1, hash2, "Hashing different passwords should produce different hashes.");

        assertNull(authenticationManager.hashPassword(null), "Hashing a null password should return null.");
    }
}
