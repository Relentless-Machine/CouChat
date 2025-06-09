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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

// TODO: Implement RSA for symmetric key exchange
// TODO: Integrate with SQLite for persistent message storage (this is the primary TODO for this feature branch) // Partially addressed
// TODO: Implement proper key management and secure storage of keys

public class MessageSecurityManager implements MessageEncryptionInterface, MessageStorageInterface {

    private static final Logger logger = LoggerFactory.getLogger(MessageSecurityManager.class);
    private static final String AES = "AES";
    private static final String DB_URL = "jdbc:sqlite:couchat_storage.db"; // Path to the SQLite database file
    private SecretKey aesKey; // In a real app, this would be derived/exchanged securely

    /**
     * Constructs a MessageSecurityManager and initializes the AES key.
     * Also ensures the database schema is created.
     * WARNING: The default AES key initialization is NOT secure for a real application.
     * Key should be securely generated, stored, and exchanged.
     */
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
        ensureDatabaseSchema();
    }

    /**
     * Constructs a MessageSecurityManager with a specific AES key.
     * Also ensures the database schema is created.
     * Used for testing or when a key is externally managed.
     *
     * @param key The AES {@link SecretKey} to use for encryption and decryption.
     */
    public MessageSecurityManager(SecretKey key) {
        this.aesKey = key;
        if (key == null) {
            logger.warn("AES key provided via constructor is null. Encryption/Decryption will fail.");
        } else {
            logger.info("AES key provided via constructor.");
        }
        ensureDatabaseSchema();
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private void ensureDatabaseSchema() {
        String createTableSql = "CREATE TABLE IF NOT EXISTS messages ("
                + "message_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "sender_id INTEGER,"
                + "receiver_id INTEGER,"
                + "message_content TEXT,"
                + "encrypted BOOLEAN,"
                + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
                + ");";

        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            // Check if messages table exists
            ResultSet rs = conn.getMetaData().getTables(null, null, "messages", null);
            if (!rs.next()) {
                logger.info("Table 'messages' does not exist. Creating it now using DB_URL: {}", DB_URL);
                stmt.execute(createTableSql);
                logger.info("Table 'messages' created successfully.");
            } else {
                logger.debug("Table 'messages' already exists.");
            }
        } catch (SQLException e) {
            logger.error("Failed to connect to or ensure database schema for 'messages' table using DB_URL: {}: ", DB_URL, e);
            // This is a critical failure for the manager's operation.
            // Consider re-throwing as a runtime exception if the application cannot proceed without the DB.
            // For now, logging the error. Subsequent operations will likely fail.
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

    // --- MessageStorageInterface Implementation (SQLite) ---

    /**
     * Saves a message to the SQLite database.
     * The message is stored as provided. If encryption is needed before saving,
     * it should be done by the caller or this method should be adapted.
     * Assumes senderId and receiverId are managed by higher-level logic (e.g., P2PConnectionManager or a UserSession).
     * For now, using placeholder IDs.
     *
     * @param message The message content to save.
     * @return The ID of the saved message, or -1 if saving failed.
     */
    @Override
    public int saveMessage(String message) {
        if (message == null) {
            logger.warn("Cannot save a null message.");
            return -1;
        }
        // Placeholder IDs, these should come from the actual session/user context
        int senderId = 1; // Example sender
        int receiverId = 2; // Example receiver
        boolean isEncrypted = true; // Assuming messages passed here are already encrypted if needed, or should be.

        String sql = "INSERT INTO messages(sender_id, receiver_id, message_content, encrypted) VALUES(?,?,?,?)";
        int messageId = -1;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setInt(1, senderId);
            pstmt.setInt(2, receiverId);
            pstmt.setString(3, message);
            pstmt.setBoolean(4, isEncrypted);
            int affectedRows = pstmt.executeUpdate();

            if (affectedRows > 0) {
                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        messageId = generatedKeys.getInt(1); // Use getInt for standard integer IDs
                        logger.info("Saved message with ID {} to SQLite: {}", messageId, message);
                    } else {
                        logger.warn("Failed to retrieve ID for saved message to SQLite (generatedKeys.next() was false, affectedRows: {}): {}", affectedRows, message);
                    }
                }
            } else {
                logger.warn("Failed to save message to SQLite (executeUpdate returned 0 or negative affectedRows: {}): {}", affectedRows, message);
            }
        } catch (SQLException e) {
            logger.error("SQLException while saving message to SQLite. DB_URL: {}", DB_URL, e);
        }
        return messageId;
    }

    /**
     * Fetches a message from the SQLite database by its ID.
     *
     * @param messageId The ID of the message to fetch.
     * @return The message content as a String, or null if not found or an error occurs.
     */
    @Override
    public String fetchMessage(int messageId) {
        String sql = "SELECT message_content FROM messages WHERE message_id = ?";
        String message = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, messageId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                message = rs.getString("message_content");
                logger.info("Fetched message with ID {} from SQLite: {}", messageId, message);
            } else {
                logger.warn("No message found with ID: {} in SQLite", messageId);
            }
        } catch (SQLException e) {
            logger.error("Failed to fetch message with ID {} from SQLite", messageId, e);
        }
        return message;
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
                logger.info("Deleted message with ID: {} from SQLite", messageId);
            } else {
                logger.warn("Cannot delete. No message found with ID: {} in SQLite", messageId);
            }
        } catch (SQLException e) {
            logger.error("Failed to delete message with ID {} from SQLite", messageId, e);
        }
    }

    // Helper to get the current AES key for testing or specific scenarios (use with caution)
    public SecretKey getAesKey() {
        return aesKey;
    }

    // Helper for tests to clear the in-memory store - This needs to be adapted or removed for SQLite
    void clearInMemoryStore() {
        // messageStore.clear();
        // messageIdCounter.set(0);
        // For SQLite, clearing would involve deleting all rows from the messages table.
        // This is a destructive operation, so be careful.
        String sql = "DELETE FROM messages";
        try (Connection conn = this.connect();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
            logger.info("Cleared all messages from SQLite 'messages' table for testing.");
        } catch (SQLException e) {
            logger.error("Failed to clear 'messages' table in SQLite for testing", e);
        }
        // Resetting an auto-increment counter in SQLite is more complex and often not done in tests.
        // Or, tests should be written to be independent of specific IDs.
        logger.debug("In-memory message store (now SQLite) cleared for testing.");
    }
}
