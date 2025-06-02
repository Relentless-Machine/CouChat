package com.couchat.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

// TODO: Implement RSA for symmetric key exchange
// TODO: Integrate with SQLite for persistent message storage (this is the primary TODO for this feature branch)
// TODO: Implement proper key management and secure storage of keys

public class MessageSecurityManager implements MessageEncryptionInterface, MessageStorageInterface {

    private static final Logger logger = LoggerFactory.getLogger(MessageSecurityManager.class);
    private static final String AES = "AES";
    private SecretKey aesKey; // In a real app, this would be derived/exchanged securely

    // In-memory storage for messages (placeholder - to be replaced by SQLite)
    private final Map<Integer, String> messageStore = new HashMap<>();
    private final AtomicInteger messageIdCounter = new AtomicInteger(0);

    public MessageSecurityManager() {
        // Initialize a placeholder AES key.
        // WARNING: This is NOT secure for a real application.
        // Key should be securely generated, stored, and exchanged.
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES);
            // Using a fixed seed for predictable keys in this example; REMOVE for production
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG"); // Or another algorithm
            secureRandom.setSeed("a_very_fixed_seed_for_testing_only_123".getBytes(StandardCharsets.UTF_8));
            keyGen.init(256, secureRandom); // AES-256
            this.aesKey = keyGen.generateKey();
            logger.info("AES key initialized (DEMO ONLY - INSECURE)");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to initialize AES key", e);
            // In a real app, this would be a critical failure.
            throw new RuntimeException("AES algorithm not found", e);
        }
    }

    // Constructor for testing with a specific key
    public MessageSecurityManager(SecretKey key) {
        this.aesKey = key;
        if (key == null) {
            logger.warn("AES key provided via constructor is null. Encryption/Decryption will fail.");
        } else {
            logger.info("AES key provided via constructor.");
        }
    }

    @Override
    public String encryptMessage(String message) throws Exception {
        if (aesKey == null) {
            logger.error("AES key is not initialized. Cannot encrypt message.");
            throw new IllegalStateException("AES key is not initialized. Cannot encrypt message.");
        }
        if (message == null) {
            logger.warn("Input message for encryption is null. Returning null.");
            return null;
        }
        logger.debug("Encrypting message: {}", message);
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        logger.debug("Encrypted message (Base64): {}", encryptedMessage);
        return encryptedMessage;
    }

    @Override
    public String decryptMessage(String encryptedMessage) throws Exception {
        if (aesKey == null) {
            logger.error("AES key is not initialized. Cannot decrypt message.");
            throw new IllegalStateException("AES key is not initialized. Cannot decrypt message.");
        }
        if (encryptedMessage == null) {
            logger.warn("Input encryptedMessage for decryption is null. Returning null.");
            return null;
        }
        logger.debug("Decrypting message (Base64): {}", encryptedMessage);
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        logger.debug("Decrypted message: {}", decryptedMessage);
        return decryptedMessage;
    }

    // --- MessageStorageInterface Implementation (Placeholder) ---
    @Override
    public void saveMessage(String message) {
        // For now, we assume the message is already encrypted if it needs to be.
        // Or, it's a raw message that this layer might encrypt before storing.
        // Let's assume 'message' is the content to be stored (could be plain or pre-encrypted).
        if (message == null) {
            logger.warn("Cannot save a null message.");
            return;
        }
        int messageId = messageIdCounter.incrementAndGet();
        messageStore.put(messageId, message);
        logger.info("Saved message with ID {}: {} (In-memory placeholder)", messageId, message);
        // TODO: Persist to SQLite instead of in-memory map
    }

    @Override
    public String fetchMessage(int messageId) {
        String message = messageStore.get(messageId);
        if (message != null) {
            logger.info("Fetched message with ID {}: {} (In-memory placeholder)", messageId, message);
        } else {
            logger.warn("No message found with ID: {} (In-memory placeholder)", messageId);
        }
        // TODO: Fetch from SQLite
        return message;
    }

    @Override
    public void deleteMessage(int messageId) {
        if (messageStore.containsKey(messageId)) {
            messageStore.remove(messageId);
            logger.info("Deleted message with ID: {} (In-memory placeholder)", messageId);
        } else {
            logger.warn("Cannot delete. No message found with ID: {} (In-memory placeholder)", messageId);
        }
        // TODO: Delete from SQLite
    }

    // Helper to get the current AES key for testing or specific scenarios (use with caution)
    public SecretKey getAesKey() {
        return aesKey;
    }

    // Helper for tests to clear the in-memory store
    void clearInMemoryStore() {
        messageStore.clear();
        messageIdCounter.set(0);
        logger.debug("In-memory message store cleared for testing.");
    }
}

