package com.couchat.security;

import org.junit.jupiter.api.AfterEach;
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
 * These tests cover encryption, decryption, and message storage functionalities,
 * ensuring messages are encrypted before being saved to the SQLite database.
 */
@ExtendWith(MockitoExtension.class)
public class MessageSecurityManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(MessageSecurityManagerTest.class);
    private MessageSecurityManager messageSecurityManager;
    private SecretKey testAesKey;
    // private static final String TEST_DB_URL = "jdbc:sqlite:test_couchat_storage.db"; // Ideal, but requires DB_URL configuration in MessageSecurityManager

    /**
     * Sets up the test environment before each test.
     * Initializes a fixed AES key for predictable encryption/decryption
     * and ensures the messages table in the database is clean.
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

        messageSecurityManager = new MessageSecurityManager(testAesKey);
        messageSecurityManager.clearMessagesTable(); // Clears the SQLite 'messages' table
        logger.info("Test AES key initialized and MessageSecurityManager (SQLite messages table) reset for test.");
    }

    /**
     * Cleans up after each test.
     */
    @AfterEach
    void tearDown() {
        // messageSecurityManager.clearMessagesTable(); // Optionally clear again
        logger.info("Test finished.");
    }

    // --- Encryption/Decryption Tests (Remain Largely Unchanged) ---

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
            String dummyEncryptedMessage = null;
            try {
                // Use the valid manager to encrypt a dummy message for testing decryption with null key
                dummyEncryptedMessage = messageSecurityManager.encryptMessage("dummy");
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

    // --- MessageStorageInterface Tests (SQLite) - Updated for new saveMessage logic ---

    /**
     * Tests saving a plain text message to SQLite (which encrypts it internally)
     * and then fetching and decrypting it.
     */
    @Test
    void testSaveAndFetchMessage_EncryptsInternally_SQLite_Success() {
        logger.info("Testing save (with internal encryption) and fetch message with SQLite.");
        String originalMessage = "Hello SQLite World! This will be encrypted by saveMessage.";
        int senderId = 101;
        int receiverId = 102;

        int messageId = messageSecurityManager.saveMessage(originalMessage, senderId, receiverId);
        assertTrue(messageId != -1, "Message ID should not be -1 after saving to SQLite.");

        String fetchedEncryptedMessage = messageSecurityManager.fetchMessage(messageId);
        assertNotNull(fetchedEncryptedMessage, "Fetched encrypted message should not be null from SQLite.");
        assertNotEquals(originalMessage, fetchedEncryptedMessage,
            "Fetched content from DB should be encrypted, not plain text.");

        try {
            String decryptedMessage = messageSecurityManager.decryptMessage(fetchedEncryptedMessage);
            assertEquals(originalMessage, decryptedMessage, "Decrypted message from SQLite should match the original plain text.");
        } catch (Exception e) {
            fail("Decryption of fetched message failed: " + e.getMessage());
        }
    }

    /**
     * Tests saving a pre-encrypted message using savePreEncryptedMessage.
     */
    @Test
    void testSavePreEncryptedMessage_SQLite_Success() {
        logger.info("Testing savePreEncryptedMessage with SQLite.");
        String originalMessage = "This is a pre-encrypted test.";
        String preEncryptedMessage = null;
        try {
            preEncryptedMessage = messageSecurityManager.encryptMessage(originalMessage); // Encrypt it first
        } catch (Exception e) {
            fail("Encryption failed during test setup: " + e.getMessage());
        }

        int senderId = 201;
        int receiverId = 202;
        int messageId = messageSecurityManager.savePreEncryptedMessage(preEncryptedMessage, senderId, receiverId, true);
        assertTrue(messageId != -1, "Message ID should not be -1 after saving pre-encrypted message.");

        String fetchedEncryptedMessage = messageSecurityManager.fetchMessage(messageId);
        assertEquals(preEncryptedMessage, fetchedEncryptedMessage, "Fetched message should match the pre-encrypted message.");

        try {
            String decryptedMessage = messageSecurityManager.decryptMessage(fetchedEncryptedMessage);
            assertEquals(originalMessage, decryptedMessage, "Decrypted pre-encrypted message should match original.");
        } catch (Exception e) {
            fail("Decryption of pre-encrypted message failed: " + e.getMessage());
        }
    }


    /**
     * Tests saving a null message using the new saveMessage(String, int, int) method.
     * Expects the operation to return -1 and not save anything.
     */
    @Test
    void testSaveMessage_SQLite_NullInput_NewMethod() {
        logger.info("Testing saving a null message to SQLite using new saveMessage method.");
        int messageId = messageSecurityManager.saveMessage(null, 1, 2);
        assertEquals(-1, messageId, "Saving a null message should return -1.");
    }

    /**
     * Tests saving a message with invalid senderId using the new saveMessage(String, int, int) method.
     */
    @Test
    void testSaveMessage_SQLite_InvalidSenderId() {
        logger.info("Testing saving a message with invalid senderId.");
        int messageId = messageSecurityManager.saveMessage("Valid message", 0, 1);
        assertEquals(-1, messageId, "Saving a message with senderId <= 0 should return -1.");
    }

    /**
     * Tests saving a message with invalid receiverId using the new saveMessage(String, int, int) method.
     */
    @Test
    void testSaveMessage_SQLite_InvalidReceiverId() {
        logger.info("Testing saving a message with invalid receiverId.");
        int messageId = messageSecurityManager.saveMessage("Valid message", 1, -1);
        assertEquals(-1, messageId, "Saving a message with receiverId <= 0 should return -1.");
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
        int senderId = 301;
        int receiverId = 302;

        int messageId = messageSecurityManager.saveMessage(message, senderId, receiverId);
        assertTrue(messageId != -1, "Message ID should not be -1 for deletion test.");

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
     * Tests saving multiple messages to SQLite (which are encrypted internally)
     * and then fetching and decrypting them to ensure correct ID assignment and retrieval.
     */
    @Test
    void testMultipleSaveAndFetch_EncryptsInternally_SQLite() {
        logger.info("Testing multiple save (with internal encryption) and fetch operations with SQLite.");
        String msg1 = "SQLite Message one - auto encrypted";
        String msg2 = "SQLite Message two - auto encrypted";
        int sender1 = 401, receiver1 = 402;
        int sender2 = 403, receiver2 = 404;

        int msgId1 = messageSecurityManager.saveMessage(msg1, sender1, receiver1);
        int msgId2 = messageSecurityManager.saveMessage(msg2, sender2, receiver2);

        assertTrue(msgId1 != -1, "Message ID 1 should not be -1.");
        assertTrue(msgId2 != -1, "Message ID 2 should not be -1.");
        assertNotEquals(msgId1, msgId2, "Message IDs should be different for distinct saves.");

        String fetchedEncMsg1 = messageSecurityManager.fetchMessage(msgId1);
        String fetchedEncMsg2 = messageSecurityManager.fetchMessage(msgId2);

        assertNotNull(fetchedEncMsg1, "Fetched encrypted message 1 should not be null.");
        assertNotNull(fetchedEncMsg2, "Fetched encrypted message 2 should not be null.");

        try {
            assertEquals(msg1, messageSecurityManager.decryptMessage(fetchedEncMsg1), "Decrypted message 1 from SQLite should match original.");
            assertEquals(msg2, messageSecurityManager.decryptMessage(fetchedEncMsg2), "Decrypted message 2 from SQLite should match original.");
        } catch (Exception e) {
            fail("Decryption failed for messages fetched from SQLite in multiple save/fetch test: " + e.getMessage());
        }
    }

    /**
     * Tests the deprecated saveMessage(String) method to ensure it still functions
     * by calling the new savePreEncryptedMessage method with placeholder values.
     * This test is for backward compatibility reassurance, though the method is deprecated.
     */
    @Test
    void testDeprecatedSaveMessage_CallsSavePreEncrypted() {
        logger.info("Testing deprecated saveMessage(String) method.");
        String originalMessage = "Testing deprecated saveMessage.";
        String preEncryptedMessage = null;
        try {
            preEncryptedMessage = messageSecurityManager.encryptMessage(originalMessage);
        } catch (Exception e) {
            fail("Encryption failed during test setup for deprecated method: " + e.getMessage());
        }

        // Call the deprecated method
        @SuppressWarnings("deprecation")
        int messageId = messageSecurityManager.saveMessage(preEncryptedMessage);
        assertTrue(messageId != -1, "Deprecated saveMessage should still save and return a valid ID.");

        String fetchedEncryptedMessage = messageSecurityManager.fetchMessage(messageId);
        assertEquals(preEncryptedMessage, fetchedEncryptedMessage,
            "Fetched message should match the pre-encrypted one saved via deprecated method.");

        try {
            String decryptedMessage = messageSecurityManager.decryptMessage(fetchedEncryptedMessage);
            assertEquals(originalMessage, decryptedMessage,
                "Decrypted message from deprecated save should match original.");
        } catch (Exception e) {
            fail("Decryption failed for message saved via deprecated method: " + e.getMessage());
        }
    }
}
