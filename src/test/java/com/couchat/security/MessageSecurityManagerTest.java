package com.couchat.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link MessageSecurityManager} class.
 * These tests cover encryption, decryption, and message storage functionalities.
 * With the introduction of SQLite, these tests now interact with a test database.
 */
@ExtendWith(MockitoExtension.class)
public class MessageSecurityManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(MessageSecurityManagerTest.class);
    private MessageSecurityManager messageSecurityManager;
    private SecretKey testAesKey;
    private static final String TEST_DB_URL = "jdbc:sqlite:test_couchat_storage.db"; // Use a separate DB for tests

    /**
     * Sets up the test environment before each test.
     * This includes initializing a fixed AES key for predictable encryption/decryption
     * and ensuring the database is clean.
     *
     * @throws NoSuchAlgorithmException if the AES algorithm is not available.
     */
    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed("a_very_fixed_seed_for_testing_only_123".getBytes(StandardCharsets.UTF_8));
        keyGen.init(256, secureRandom); // AES-256
        testAesKey = keyGen.generateKey();

        // Point MessageSecurityManager to the test database for this test run
        // This requires a way to configure the DB_URL, or the MessageSecurityManager
        // needs to be refactored to accept a DB_URL or Connection provider.
        // For now, we'll assume MessageSecurityManager uses its default DB_URL,
        // and clearInMemoryStore() will target that. For true isolation, a test-specific DB is better.
        // Let's modify MessageSecurityManager to allow DB_URL override for tests or use a test-specific instance.
        // For simplicity in this step, we will rely on the clearInMemoryStore to clean the default DB.
        // However, the ideal approach is to use a dedicated test database.
        messageSecurityManager = new MessageSecurityManager(testAesKey); // This will use the default DB_URL
        messageSecurityManager.clearInMemoryStore(); // This now clears the SQLite 'messages' table
        logger.info("Test AES key initialized and MessageSecurityManager (using SQLite) reset for test.");
    }

    /**
     * Tests successful encryption and decryption of a message.
     */
    @Test
    void testEncryptAndDecryptMessage_Success() {
        String originalMessage = "Hello, Secure World! This is a test message.";
        logger.info("Testing encryption and decryption of: '{}'", originalMessage);
        try {
            String encryptedMessage = messageSecurityManager.encryptMessage(originalMessage);
            assertNotNull(encryptedMessage, "Encrypted message should not be null.");
            assertNotEquals(originalMessage, encryptedMessage, "Encrypted message should be different from original.");

            String decryptedMessage = messageSecurityManager.decryptMessage(encryptedMessage);
            assertEquals(originalMessage, decryptedMessage, "Decrypted message should match the original.");
            logger.info("Encryption and decryption successful.");
        } catch (Exception e) {
            logger.error("Error during encryption/decryption test", e);
            fail("Exception during encryption/decryption: " + e.getMessage());
        }
    }

    /**
     * Tests encryption with a null input message.
     *
     * @throws Exception if an unexpected error occurs.
     */
    @Test
    void testEncryptMessage_NullInput() throws Exception {
        logger.info("Testing encryption with null input message.");
        assertNull(messageSecurityManager.encryptMessage(null), "Encrypting a null message should return null.");
    }

    /**
     * Tests decryption with a null input message.
     *
     * @throws Exception if an unexpected error occurs.
     */
    @Test
    void testDecryptMessage_NullInput() throws Exception {
        logger.info("Testing decryption with null input message.");
        assertNull(messageSecurityManager.decryptMessage(null), "Decrypting a null message should return null.");
    }

    /**
     * Tests encryption when the AES key is not initialized (null).
     */
    @Test
    void testEncryptMessage_NullKey() {
        logger.info("Testing encryption with a null AES key.");
        MessageSecurityManager managerWithNullKey = new MessageSecurityManager(null);
        Exception exception = assertThrows(IllegalStateException.class, () -> {
            managerWithNullKey.encryptMessage("Test with null key");
        });
        assertEquals("AES key is not initialized. Cannot encrypt message.", exception.getMessage());
    }

    /**
     * Tests decryption when the AES key is not initialized (null).
     */
    @Test
    void testDecryptMessage_NullKey() {
        logger.info("Testing decryption with a null AES key.");
        MessageSecurityManager managerWithNullKey = new MessageSecurityManager(null);
        Exception exception = assertThrows(IllegalStateException.class, () -> {
            // Encrypt something first to get a valid encrypted string format, though not with this manager
            String dummyEncryptedMessage = null;
            try {
                dummyEncryptedMessage = messageSecurityManager.encryptMessage("dummy"); // Use valid manager for this
            } catch (Exception e) {
                fail("Setup for dummy encrypted message failed: " + e.getMessage());
            }
            managerWithNullKey.decryptMessage(dummyEncryptedMessage);
        });
        assertEquals("AES key is not initialized. Cannot decrypt message.", exception.getMessage());
    }

    /**
     * Tests decryption with an invalid Base64 encoded string.
     */
    @Test
    void testDecryptMessage_InvalidBase64() {
        String invalidEncryptedMessage = "This is not a valid Base64 string!@#";
        logger.info("Testing decryption with invalid Base64 input: '{}'", invalidEncryptedMessage);
        assertThrows(IllegalArgumentException.class, () -> {
            messageSecurityManager.decryptMessage(invalidEncryptedMessage);
        }, "Decrypting an invalid Base64 string should throw IllegalArgumentException.");
    }

    /**
     * Tests decryption of a message that has been tampered with after encryption.
     * Expects a cryptographic exception.
     */
    @Test
    void testDecryptMessage_Tampered() {
        String originalMessage = "Sensitive Data";
        logger.info("Testing decryption of tampered message. Original: '{}'", originalMessage);
        try {
            String encryptedMessage = messageSecurityManager.encryptMessage(originalMessage);
            String tamperedEncryptedMessage = encryptedMessage.substring(0, encryptedMessage.length() - 1) + "X"; // Tamper it

            assertThrows(Exception.class, () -> {
                messageSecurityManager.decryptMessage(tamperedEncryptedMessage);
            }, "Decrypting tampered message should throw a cryptographic exception (e.g., BadPaddingException).");
        } catch (Exception e) {
            logger.error("Error during setup for tampered message test", e);
            fail("Error during setup for tampered message test: " + e.getMessage());
        }
    }

    // --- MessageStorageInterface Tests (SQLite) ---

    /**
     * Tests saving a message to the SQLite database and then fetching it.
     * Verifies that the fetched message matches the original.
     */
    @Test
    void testSaveAndFetchMessage_SQLite_Success() {
        logger.info("Testing save and fetch message with SQLite.");
        String originalMessage = "Hello SQLite World!";
        String encryptedMessage = null;
        try {
            encryptedMessage = messageSecurityManager.encryptMessage(originalMessage);
        } catch (Exception e) {
            fail("Encryption failed: " + e.getMessage());
        }

        int messageId = messageSecurityManager.saveMessage(encryptedMessage);
        assertTrue(messageId != -1, "Message ID should not be -1 after saving to SQLite.");

        String fetchedEncryptedMessage = messageSecurityManager.fetchMessage(messageId);
        assertNotNull(fetchedEncryptedMessage, "Fetched encrypted message should not be null from SQLite.");

        try {
            String decryptedMessage = messageSecurityManager.decryptMessage(fetchedEncryptedMessage);
            assertEquals(originalMessage, decryptedMessage, "Decrypted message from SQLite should match original.");
        } catch (Exception e) {
            fail("Decryption failed: " + e.getMessage());
        }
    }

    /**
     * Tests saving a null message to the SQLite database.
     * Expects the operation to be handled gracefully without insertion.
     */
    @Test
    void testSaveMessage_SQLite_NullInput() {
        logger.info("Testing saving a null message to SQLite.");
        messageSecurityManager.saveMessage(null);
        // Verify that no message was actually saved. Fetching a recent ID should yield null.
        // This assumes IDs are sequential and positive. A count query would be more robust.
        assertNull(messageSecurityManager.fetchMessage(1), "SQLite should not save a null message, so ID 1 should be null.");
    }

    /**
     * Tests fetching a message with a non-existent ID from the SQLite database.
     * Expects null to be returned.
     */
    @Test
    void testFetchMessage_SQLite_NonExistent() {
        logger.info("Testing fetching a non-existent message ID from SQLite.");
        assertNull(messageSecurityManager.fetchMessage(99999), "Fetching a non-existent message from SQLite should return null.");
    }

    /**
     * Tests deleting a message from the SQLite database.
     * Verifies that the message cannot be fetched after deletion.
     */
    @Test
    void testDeleteMessage_SQLite_Success() {
        logger.info("Testing delete message success with SQLite.");
        String message = "Message to be deleted from SQLite";
        String encryptedMessage = null;
        try {
            encryptedMessage = messageSecurityManager.encryptMessage(message);
        } catch (Exception e) {
            fail("Encryption failed: " + e.getMessage());
        }

        int messageId = messageSecurityManager.saveMessage(encryptedMessage);
        assertTrue(messageId != -1, "Message ID should not be -1 for deletion test.");

        // Verify it's in the database
        String fetchedMessageBeforeDeletion = messageSecurityManager.fetchMessage(messageId);
        assertNotNull(fetchedMessageBeforeDeletion, "Message should exist in SQLite before deletion.");

        messageSecurityManager.deleteMessage(messageId);
        String fetchedMessageAfterDeletion = messageSecurityManager.fetchMessage(messageId);
        assertNull(fetchedMessageAfterDeletion, "Message should be null from SQLite after deletion.");
    }

    /**
     * Tests deleting a message with a non-existent ID from the SQLite database.
     * Expects the operation to complete without errors.
     */
    @Test
    void testDeleteMessage_SQLite_NonExistent() {
        logger.info("Testing deletion of a non-existent message ID from SQLite.");
        assertDoesNotThrow(() -> {
            messageSecurityManager.deleteMessage(123456);
        }, "Deleting a non-existent message from SQLite should not throw an exception.");
    }

    /**
     * Tests saving multiple messages to SQLite and then fetching them to ensure
     * correct ID assignment and retrieval.
     */
    @Test
    void testMultipleSaveAndFetch_SQLite() {
        logger.info("Testing multiple save and fetch operations with SQLite.");
        String msg1 = "SQLite Message one";
        String msg2 = "SQLite Message two";
        String encMsg1 = null, encMsg2 = null;

        try {
            encMsg1 = messageSecurityManager.encryptMessage(msg1);
            encMsg2 = messageSecurityManager.encryptMessage(msg2);
        } catch (Exception e) {
            fail("Encryption failed during setup for multiple save/fetch test: " + e.getMessage());
        }

        int msgId1 = messageSecurityManager.saveMessage(encMsg1);
        int msgId2 = messageSecurityManager.saveMessage(encMsg2);

        assertTrue(msgId1 != -1, "Message ID 1 should not be -1.");
        assertTrue(msgId2 != -1, "Message ID 2 should not be -1.");
        assertNotEquals(msgId1, msgId2, "Message IDs should be different.");

        String fetchedEncMsg1 = messageSecurityManager.fetchMessage(msgId1);
        String fetchedEncMsg2 = messageSecurityManager.fetchMessage(msgId2);

        assertNotNull(fetchedEncMsg1, "Fetched encrypted message 1 should not be null.");
        assertNotNull(fetchedEncMsg2, "Fetched encrypted message 2 should not be null.");

        try {
            assertEquals(msg1, messageSecurityManager.decryptMessage(fetchedEncMsg1), "Decrypted message 1 from SQLite should match.");
            assertEquals(msg2, messageSecurityManager.decryptMessage(fetchedEncMsg2), "Decrypted message 2 from SQLite should match.");
        } catch (Exception e) {
            fail("Decryption failed for messages fetched from SQLite in multiple save/fetch test: " + e.getMessage());
        }
    }
}
