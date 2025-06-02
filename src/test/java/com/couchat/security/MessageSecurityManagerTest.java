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

@ExtendWith(MockitoExtension.class)
public class MessageSecurityManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(MessageSecurityManagerTest.class);
    private MessageSecurityManager messageSecurityManager;
    private SecretKey testAesKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed("a_very_fixed_seed_for_testing_only_123".getBytes(StandardCharsets.UTF_8));
        keyGen.init(256, secureRandom); // AES-256
        testAesKey = keyGen.generateKey();
        messageSecurityManager = new MessageSecurityManager(testAesKey);
        messageSecurityManager.clearInMemoryStore(); // Ensure clean state for each test
        logger.info("Test AES key initialized and MessageSecurityManager reset for test.");
    }

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

    @Test
    void testEncryptMessage_NullInput() throws Exception {
        logger.info("Testing encryption with null input message.");
        assertNull(messageSecurityManager.encryptMessage(null), "Encrypting a null message should return null.");
    }

    @Test
    void testDecryptMessage_NullInput() throws Exception {
        logger.info("Testing decryption with null input message.");
        assertNull(messageSecurityManager.decryptMessage(null), "Decrypting a null message should return null.");
    }

    @Test
    void testEncryptMessage_NullKey() {
        logger.info("Testing encryption with a null AES key.");
        MessageSecurityManager managerWithNullKey = new MessageSecurityManager(null);
        Exception exception = assertThrows(IllegalStateException.class, () -> {
            managerWithNullKey.encryptMessage("Test with null key");
        });
        assertEquals("AES key is not initialized. Cannot encrypt message.", exception.getMessage());
    }

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

    @Test
    void testDecryptMessage_InvalidBase64() {
        String invalidEncryptedMessage = "This is not a valid Base64 string!@#";
        logger.info("Testing decryption with invalid Base64 input: '{}'", invalidEncryptedMessage);
        assertThrows(IllegalArgumentException.class, () -> {
            messageSecurityManager.decryptMessage(invalidEncryptedMessage);
        }, "Decrypting an invalid Base64 string should throw IllegalArgumentException.");
    }

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

    // --- MessageStorageInterface Tests (In-Memory Placeholder) ---
    @Test
    void testSaveAndFetchMessage_Success() {
        String testMessage = "This is a message to be stored (encrypted).";
        logger.info("Testing save and fetch for message: '{}'", testMessage);
        messageSecurityManager.saveMessage(testMessage); // Assuming testMessage is already "encrypted"

        // Fetch by ID. Since counter starts at 0 and increments before put, first ID is 1.
        String fetchedMessage = messageSecurityManager.fetchMessage(1);
        assertNotNull(fetchedMessage, "Fetched message should not be null.");
        assertEquals(testMessage, fetchedMessage, "Fetched message should match the stored message.");
    }

    @Test
    void testSaveMessage_NullInput() {
        logger.info("Testing saving a null message.");
        messageSecurityManager.saveMessage(null);
        // Check that the store size hasn't changed or that a specific ID wasn't created.
        // For this placeholder, we'll check if fetching a new ID returns null.
        assertNull(messageSecurityManager.fetchMessage(1), "Store should not save a null message, so ID 1 should be null.");
    }

    @Test
    void testFetchMessage_NonExistent() {
        logger.info("Testing fetching a non-existent message ID.");
        assertNull(messageSecurityManager.fetchMessage(999), "Fetching a non-existent message should return null.");
    }

    @Test
    void testDeleteMessage_Success() {
        String messageToSaveAndDetect = "A message to delete.";
        logger.info("Testing deletion of message: '{}'", messageToSaveAndDetect);
        messageSecurityManager.saveMessage(messageToSaveAndDetect); // ID will be 1
        assertNotNull(messageSecurityManager.fetchMessage(1), "Message should exist before deletion.");

        messageSecurityManager.deleteMessage(1);
        assertNull(messageSecurityManager.fetchMessage(1), "Message should not exist after deletion.");
    }

    @Test
    void testDeleteMessage_NonExistent() {
        logger.info("Testing deletion of a non-existent message ID.");
        assertDoesNotThrow(() -> {
            messageSecurityManager.deleteMessage(12345);
        }, "Deleting a non-existent message should not throw an exception.");
    }

    @Test
    void testMultipleSaveAndFetch() {
        logger.info("Testing multiple save and fetch operations.");
        String msg1 = "Message one";
        String msg2 = "Message two";
        messageSecurityManager.saveMessage(msg1); // ID 1
        messageSecurityManager.saveMessage(msg2); // ID 2

        assertEquals(msg1, messageSecurityManager.fetchMessage(1), "Fetched message 1 should match.");
        assertEquals(msg2, messageSecurityManager.fetchMessage(2), "Fetched message 2 should match.");
    }
}

