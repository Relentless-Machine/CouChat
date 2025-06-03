package com.couchat.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationManagerTest.class);
    private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        authenticationManager = new AuthenticationManager();
        authenticationManager.clearAllAuthentications(); // Clear state before each test
        logger.info("AuthenticationManager initialized and cleared for test.");
    }

    @Test
    void testAuthenticateUser_Success() {
        logger.info("Testing successful user authentication.");
        authenticationManager.authenticateUser("testuser", "password123");
        assertTrue(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should be logged in after successful placeholder authentication.");
    }

    @Test
    void testAuthenticateUser_Failure_WrongPassword() {
        logger.info("Testing failed user authentication due to wrong password.");
        authenticationManager.authenticateUser("testuser", "wrongpassword");
        assertFalse(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should not be logged in with wrong password.");
    }

    @Test
    void testAuthenticateUser_Failure_UnknownUser() {
        logger.info("Testing failed user authentication for an unknown user.");
        authenticationManager.authenticateUser("unknownuser", "password123");
        assertFalse(authenticationManager.isUserLoggedIn("unknownuser"),
                "Unknown user should not be logged in.");
    }

    @Test
    void testAuthenticateUser_NullUsername() {
        logger.info("Testing user authentication with null username.");
        authenticationManager.authenticateUser(null, "password123");
        // No specific user to check, but no exception should be thrown, and no one should be logged in as null
        assertFalse(authenticationManager.isUserLoggedIn(null), "Null user should not be logged in.");
    }

    @Test
    void testAuthenticateUser_EmptyPassword() {
        logger.info("Testing user authentication with empty password.");
        authenticationManager.authenticateUser("testuser", "");
        assertFalse(authenticationManager.isUserLoggedIn("testuser"),
                "User 'testuser' should not be logged in with an empty password.");
    }

    @Test
    void testAuthenticateWithOAuth_Success() {
        String oauthToken = "valid_oauth_token_for_testuser";
        logger.info("Testing successful OAuth authentication with token: {}", oauthToken);
        authenticationManager.authenticateWithOAuth(oauthToken);
        assertTrue(authenticationManager.isUserLoggedIn("test_oauth_user"),
                "'test_oauth_user' should be logged in after successful OAuth.");
    }

    @Test
    void testAuthenticateWithOAuth_Failure_InvalidToken() {
        String invalidToken = "invalid_oauth_token";
        logger.info("Testing failed OAuth authentication with invalid token: {}", invalidToken);
        authenticationManager.authenticateWithOAuth(invalidToken);
        assertFalse(authenticationManager.isUserLoggedIn("test_oauth_user"), // Assuming no user is logged in with this token
                "No user should be logged in with an invalid OAuth token.");
    }

    @Test
    void testAuthenticateWithOAuth_NullToken() {
        logger.info("Testing OAuth authentication with null token.");
        authenticationManager.authenticateWithOAuth(null);
        assertFalse(authenticationManager.isUserLoggedIn("test_oauth_user"),
                "No user should be logged in with a null OAuth token.");
    }

    @Test
    void testBindDevicePasskey_Success() {
        String deviceId = "testDevice123";
        String passkey = "strongPasskey456";
        String username = "testuser";
        String password = "password123";

        // Ensure the user is logged in before binding a passkey
        authenticationManager.authenticateUser(username, password);
        assertTrue(authenticationManager.isUserLoggedIn(username), "User '" + username + "' should be logged in before binding passkey.");

        logger.info("Testing successful device passkey binding for device: {}, passkey: {}", deviceId, passkey);
        authenticationManager.bindDevicePasskey(deviceId, passkey);

        // Use the same hashing mechanism as the manager for verification
        String expectedPasskeyHash = authenticationManager.hashPassword(passkey);
        assertEquals(expectedPasskeyHash, authenticationManager.getBoundPasskeyHash(deviceId),
                "Passkey hash should be correctly stored for the device.");
    }

    @Test
    void testBindDevicePasskey_NullDeviceId() {
        logger.info("Testing device passkey binding with null device ID.");
        authenticationManager.bindDevicePasskey(null, "strongPasskey789");
        // No specific assertion on stored value, but ensure no exception and no unintended bindings.
        // Check that a lookup for null deviceId doesn't yield the passkey.
        assertNull(authenticationManager.getBoundPasskeyHash(null));
    }

    @Test
    void testBindDevicePasskey_EmptyPasskey() {
        String deviceId = "testDevice456";
        logger.info("Testing device passkey binding with empty passkey for device: {}", deviceId);
        authenticationManager.bindDevicePasskey(deviceId, "");
        assertNull(authenticationManager.getBoundPasskeyHash(deviceId),
                "Passkey should not be bound if it's empty.");
    }

    @Test
    void testIsUserLoggedIn_False_UnknownUser() {
        logger.info("Testing isUserLoggedIn for a non-existent/unknown user.");
        assertFalse(authenticationManager.isUserLoggedIn("nonexistentuser"),
                "A user not explicitly logged in or unknown should return false.");
    }

    @Test
    void testIsUserLoggedIn_False_AfterFailedLogin() {
        logger.info("Testing isUserLoggedIn after a failed login attempt.");
        authenticationManager.authenticateUser("testuser", "wrongpass");
        assertFalse(authenticationManager.isUserLoggedIn("testuser"),
                "User should not be logged in after a failed login attempt.");
    }
}

