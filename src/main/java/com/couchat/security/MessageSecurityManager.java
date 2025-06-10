package com.couchat.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service; // Import @Service

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;

/**
 * Manages message encryption, decryption, and persistent storage in an SQLite database.
 * This class handles AES encryption for message content and interacts with the
 * database to save, fetch, and delete messages.
 */
@Service // Add @Service annotation to make it a Spring bean
public class MessageSecurityManager implements MessageEncryptionInterface, MessageStorageInterface {

    private static final Logger logger = LoggerFactory.getLogger(MessageSecurityManager.class);
    private static final String AES_ALGORITHM = "AES";
    private static final String DB_URL = "jdbc:sqlite:couchat_storage.db";
    private SecretKey aesKey; // Represents the current symmetric key for a session/user.

    /**
     * Constructs a MessageSecurityManager.
     * Initializes a placeholder AES key for demonstration and testing purposes.
     * Ensures the database schema for messages is created.
     * <p>
     * WARNING: The default AES key initialization in this constructor is NOT secure
     * for a real application. In a production environment, AES keys should be
     * securely generated (e.g., per session or per user pair), exchanged using
     * an asymmetric protocol like RSA, and managed securely.
     * </p>
     */
    public MessageSecurityManager() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            // Using a fixed seed for predictable keys in this example; REMOVE for production.
            // This makes tests predictable but is a major security flaw in production.
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed("a_very_fixed_seed_for_testing_only_123".getBytes(StandardCharsets.UTF_8));
            keyGen.init(256, secureRandom); // AES-256
            this.aesKey = keyGen.generateKey();
            logger.info("AES key initialized (DEMO ONLY - INSECURE FIXED SEED).");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to initialize AES key generator: {}", e.getMessage(), e);
            throw new RuntimeException("AES algorithm not found, critical for MessageSecurityManager.", e);
        }
        ensureDatabaseSchema();
    }

    /**
     * Constructs a MessageSecurityManager with a specific AES {@link SecretKey}.
     * This constructor is typically used for testing or when the AES key is managed externally.
     * Ensures the database schema for messages is created.
     *
     * @param key The AES {@link SecretKey} to use for encryption and decryption.
     *            If null, encryption/decryption operations will fail.
     */
    public MessageSecurityManager(SecretKey key) {
        this.aesKey = key;
        if (key == null) {
            logger.warn("AES key provided via constructor is null. Encryption/Decryption operations will fail.");
        } else {
            logger.info("AES key provided via constructor.");
        }
        ensureDatabaseSchema();
    }

    /**
     * Encrypts a plain text message using the current AES key. This method is suitable for direct encryption
     * without database interaction, for example, for API endpoints.
     *
     * @param plainMessage The plain text message to encrypt.
     * @return The Base64 encoded string of the encrypted message.
     * @throws IllegalStateException if the AES key is not initialized.
     * @throws Exception             if any other error occurs during encryption.
     */
    public String encryptDirect(String plainMessage) throws Exception {
        return encryptMessage(plainMessage); // Reuses the existing encryptMessage logic
    }

    /**
     * Decrypts a Base64 encoded encrypted message using the current AES key. This method is suitable for direct
     * decryption without database interaction, for example, for API endpoints.
     *
     * @param encryptedMessageBase64 The Base64 encoded encrypted message.
     * @return The decrypted plain text message.
     * @throws IllegalStateException if the AES key is not initialized.
     * @throws Exception             if any other error occurs during decryption.
     */
    public String decryptDirect(String encryptedMessageBase64) throws Exception {
        return decryptMessage(encryptedMessageBase64); // Reuses the existing decryptMessage logic
    }

    /**
     * Establishes a connection to the SQLite database.
     *
     * @return A {@link Connection} object to the database.
     * @throws SQLException if a database access error occurs.
     */
    private Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    /**
     * Ensures that the 'messages' table exists in the database.
     * If the table does not exist, it is created.
     */
    private void ensureDatabaseSchema() {
        String createTableSql = "CREATE TABLE IF NOT EXISTS messages ("
                + "message_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "sender_id INTEGER NOT NULL," // Added NOT NULL
                + "receiver_id INTEGER NOT NULL," // Added NOT NULL
                + "message_content TEXT NOT NULL," // Added NOT NULL (stores encrypted content)
                + "encrypted BOOLEAN NOT NULL DEFAULT TRUE," // Ensure it's always marked, default to true
                + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
                + ");";

        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
            logger.debug("Ensured 'messages' table exists in database: {}", DB_URL);
        } catch (SQLException e) {
            logger.error("Failed to connect to or ensure 'messages' table schema using DB_URL: {}. Error: {}", DB_URL, e.getMessage(), e);
            // This is a critical failure. For a robust application, consider specific recovery or notification.
        }
    }

    /**
     * Encrypts a plain text message using the current AES key.
     *
     * @param plainMessage The plain text message to encrypt.
     * @return The Base64 encoded string of the encrypted message.
     * @throws IllegalStateException if the AES key is not initialized.
     * @throws Exception             if any other error occurs during encryption.
     */
    @Override
    public String encryptMessage(String plainMessage) throws Exception {
        if (aesKey == null) {
            logger.error("AES key is not initialized. Cannot encrypt message.");
            throw new IllegalStateException("AES key is not initialized. Cannot encrypt message.");
        }
        if (plainMessage == null) {
            logger.warn("Input message for encryption is null. Returning null.");
            return null;
        }
        logger.debug("Encrypting message (first 20 chars): '{}...'", plainMessage.substring(0, Math.min(plainMessage.length(), 20)));
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedBytes = cipher.doFinal(plainMessage.getBytes(StandardCharsets.UTF_8));
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
        logger.debug("Encrypted message (Base64, first 20 chars): '{}...'", encryptedMessageBase64.substring(0, Math.min(encryptedMessageBase64.length(), 20)));
        return encryptedMessageBase64;
    }

    /**
     * Decrypts a Base64 encoded encrypted message using the current AES key.
     *
     * @param encryptedMessageBase64 The Base64 encoded encrypted message.
     * @return The decrypted plain text message.
     * @throws IllegalStateException if the AES key is not initialized.
     * @throws Exception             if any other error occurs during decryption (e.g., invalid format, bad padding).
     */
    @Override
    public String decryptMessage(String encryptedMessageBase64) throws Exception {
        if (aesKey == null) {
            logger.error("AES key is not initialized. Cannot decrypt message.");
            throw new IllegalStateException("AES key is not initialized. Cannot decrypt message.");
        }
        if (encryptedMessageBase64 == null) {
            logger.warn("Input encryptedMessage for decryption is null. Returning null.");
            return null;
        }
        logger.debug("Decrypting message (Base64, first 20 chars): '{}...'", encryptedMessageBase64.substring(0, Math.min(encryptedMessageBase64.length(), 20)));
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessageBase64);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        logger.debug("Decrypted message (first 20 chars): '{}...'", decryptedMessage.substring(0, Math.min(decryptedMessage.length(), 20)));
        return decryptedMessage;
    }

    /**
     * Encrypts and saves a message to the SQLite database.
     * The method first encrypts the plain text message using the current AES key,
     * then stores the encrypted content.
     *
     * @param plainMessage The plain text message to encrypt and save.
     * @param senderId     The ID of the message sender.
     * @param receiverId   The ID of the message receiver.
     * @return The ID of the saved message in the database, or -1 if saving failed or encryption failed.
     */
    public int saveMessage(String plainMessage, int senderId, int receiverId) {
        if (plainMessage == null) {
            logger.warn("Cannot save a null message.");
            return -1;
        }
        if (senderId <= 0 || receiverId <= 0) {
            logger.warn("Cannot save message with invalid senderId ({}) or receiverId ({}).", senderId, receiverId);
            return -1;
        }

        String encryptedMessage;
        try {
            encryptedMessage = encryptMessage(plainMessage);
            if (encryptedMessage == null) { // Should not happen if plainMessage is not null and key is init
                logger.error("Encryption returned null for a non-null message. Aborting save.");
                return -1;
            }
        } catch (Exception e) {
            logger.error("Failed to encrypt message before saving. Sender: {}, Receiver: {}. Error: {}", senderId, receiverId, e.getMessage(), e);
            return -1;
        }

        String sql = "INSERT INTO messages(sender_id, receiver_id, message_content, encrypted) VALUES(?,?,?,?)";
        int messageId = -1;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setInt(1, senderId);
            pstmt.setInt(2, receiverId);
            pstmt.setString(3, encryptedMessage); // Store the encrypted message
            pstmt.setBoolean(4, true);           // Mark as encrypted

            int affectedRows = pstmt.executeUpdate();

            if (affectedRows > 0) {
                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        messageId = generatedKeys.getInt(1);
                        logger.info("Saved encrypted message with ID {} to SQLite. Sender: {}, Receiver: {}.", messageId, senderId, receiverId);
                    } else {
                        logger.warn("Failed to retrieve ID for saved message (sender: {}, receiver: {}). Affected rows: {}.", senderId, receiverId, affectedRows);
                    }
                }
            } else {
                logger.warn("Failed to save message to SQLite (sender: {}, receiver: {}). No rows affected.", senderId, receiverId);
            }
        } catch (SQLException e) {
            logger.error("SQLException while saving message to SQLite (sender: {}, receiver: {}). DB_URL: {}. Error: {}", senderId, receiverId, DB_URL, e.getMessage(), e);
        }
        return messageId;
    }

    /**
     * Saves a pre-encrypted message to the SQLite database.
     * This method is kept for scenarios where the message is already encrypted externally.
     *
     * @param encryptedMessage The pre-encrypted message content to save.
     * @param senderId     The ID of the message sender.
     * @param receiverId   The ID of the message receiver.
     * @param isEncrypted  A boolean flag indicating if the messageContent is indeed encrypted.
     * @return The ID of the saved message, or -1 if saving failed.
     */
    public int savePreEncryptedMessage(String encryptedMessage, int senderId, int receiverId, boolean isEncrypted) {
        if (encryptedMessage == null) {
            logger.warn("Cannot save a null pre-encrypted message.");
            return -1;
        }
         if (senderId <= 0 || receiverId <= 0) {
            logger.warn("Cannot save pre-encrypted message with invalid senderId ({}) or receiverId ({}).", senderId, receiverId);
            return -1;
        }

        String sql = "INSERT INTO messages(sender_id, receiver_id, message_content, encrypted) VALUES(?,?,?,?)";
        int messageId = -1;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setInt(1, senderId);
            pstmt.setInt(2, receiverId);
            pstmt.setString(3, encryptedMessage);
            pstmt.setBoolean(4, isEncrypted);
            int affectedRows = pstmt.executeUpdate();

            if (affectedRows > 0) {
                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        messageId = generatedKeys.getInt(1);
                        logger.info("Saved pre-encrypted message with ID {} to SQLite. Sender: {}, Receiver: {}, Encrypted: {}", messageId, senderId, receiverId, isEncrypted);
                    } else {
                         logger.warn("Failed to retrieve ID for saved pre-encrypted message (sender: {}, receiver: {}). Affected rows: {}.", senderId, receiverId, affectedRows);
                    }
                }
            } else {
                logger.warn("Failed to save pre-encrypted message to SQLite (sender: {}, receiver: {}). No rows affected.", senderId, receiverId);
            }
        } catch (SQLException e) {
            logger.error("SQLException while saving pre-encrypted message to SQLite (sender: {}, receiver: {}). DB_URL: {}. Error: {}", senderId, receiverId, DB_URL, e.getMessage(), e);
        }
        return messageId;
    }


    /**
     * Fetches an encrypted message from the SQLite database by its ID.
     * The caller is responsible for decrypting the message if needed.
     *
     * @param messageId The ID of the message to fetch.
     * @return The encrypted message content as a String, or null if not found or an error occurs.
     */
    @Override
    public String fetchMessage(int messageId) {
        String sql = "SELECT message_content FROM messages WHERE message_id = ?";
        String encryptedMessage = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, messageId);
            try (ResultSet rs = pstmt.executeQuery()) { // Ensure ResultSet is closed
                if (rs.next()) {
                    encryptedMessage = rs.getString("message_content");
                    logger.info("Fetched encrypted message with ID {} from SQLite.", messageId);
                } else {
                    logger.warn("No message found with ID: {} in SQLite.", messageId);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to fetch message with ID {} from SQLite. Error: {}", messageId, e.getMessage(), e);
        }
        return encryptedMessage;
    }

    /**
     * Deletes a message from the SQLite database by its ID.
     *
     * @param messageId The ID of the message to delete.
     */
    @Override
    public void deleteMessage(int messageId) {
        String sql = "DELETE FROM messages WHERE message_id = ?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, messageId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                logger.info("Deleted message with ID: {} from SQLite.", messageId);
            } else {
                logger.warn("Cannot delete. No message found with ID: {} in SQLite, or delete failed.", messageId);
            }
        } catch (SQLException e) {
            logger.error("Failed to delete message with ID {} from SQLite. Error: {}", messageId, e.getMessage(), e);
        }
    }

    /**
     * Retrieves the current AES {@link SecretKey} used by this manager.
     * This method should be used with caution, primarily for testing or specific
     * key management scenarios where direct key access is required.
     *
     * @return The current AES {@link SecretKey}.
     */
    public SecretKey getAesKey() {
        return aesKey;
    }

    /**
     * Clears all messages from the 'messages' table in the SQLite database.
     * This is a destructive operation and is primarily intended for use in test environments
     * to ensure a clean state before or after tests.
     */
    void clearMessagesTable() {
        String sql = "DELETE FROM messages";
        // Optional: Reset auto-increment counter if necessary for specific test scenarios,
        // though generally tests should not rely on specific auto-incremented ID values.
        // String resetSql = "DELETE FROM sqlite_sequence WHERE name='messages';"; // For SQLite
        try (Connection conn = this.connect();
             Statement stmt = conn.createStatement()) {
            int deletedRows = stmt.executeUpdate(sql);
            logger.info("Cleared all {} messages from SQLite 'messages' table for testing.", deletedRows);
            // stmt.executeUpdate(resetSql); // If you need to reset auto-increment
        } catch (SQLException e) {
            logger.error("Failed to clear 'messages' table in SQLite for testing. Error: {}", e.getMessage(), e);
        }
    }

    // Interface methods from MessageStorageInterface that were previously implemented
    // with different signatures or logic are now updated or consolidated.
    // The public `saveMessage(String plainMessage, int senderId, int receiverId)` is the primary save method.
    // The old `saveMessage(String message)` is effectively replaced.

    /**
     * @deprecated This method is deprecated. Use {@link #saveMessage(String, int, int)}
     * or {@link #savePreEncryptedMessage(String, int, int, boolean)} instead.
     * It previously saved a message with placeholder sender/receiver IDs and assumed
     * the message was pre-encrypted.
     */
    @Deprecated
    @Override
    public int saveMessage(String message) {
        logger.warn("Deprecated saveMessage(String) called. Use saveMessage(String, int, int) or savePreEncryptedMessage(...) instead.");
        // Providing a fallback behavior or throwing an UnsupportedOperationException might be alternatives.
        // For now, let's call the pre-encrypted version with placeholder IDs and assuming it's encrypted.
        return savePreEncryptedMessage(message, 1, 2, true); // Placeholder IDs
    }
}
