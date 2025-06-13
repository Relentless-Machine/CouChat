package com.couchat.repository.impl;

import com.couchat.messaging.model.Message;
import com.couchat.repository.MessageRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
// Assuming Message.java will be refactored to have a constructor suitable for DB mapping
// import com.couchat.messaging.model.Message.MessageType; // Already imported via Message
// import com.couchat.messaging.model.Message.MessageStatus; // Already imported via Message

/**
 * JDBC implementation of the {@link MessageRepository} interface.
 * Handles database operations for {@link Message} entities using JdbcTemplate.
 */
@Repository
public class JdbcMessageRepository implements MessageRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcMessageRepository.class);
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    /**
     * Constructs a new JdbcMessageRepository.
     *
     * @param jdbcTemplate The JdbcTemplate to use for database access.
     * @param objectMapper The ObjectMapper for JSON serialization/deserialization.
     */
    @Autowired
    public JdbcMessageRepository(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        // Ensure JavaTimeModule is registered if not done globally
        if (!this.objectMapper.getRegisteredModuleIds().contains(JavaTimeModule.class.getName())) {
            this.objectMapper.registerModule(new JavaTimeModule());
        }
    }

    /**
     * RowMapper to map a ResultSet row to a {@link Message} object.
     * This RowMapper assumes that {@link Message} has a constructor or setters
     * that allow all fields fetched from the database to be set.
     */
    private RowMapper<Message> messageRowMapper() {
        return (rs, rowNum) -> {
            String messageId = rs.getString("message_id");
            String conversationId = rs.getString("conversation_id");
            String senderId = rs.getString("sender_id");
            String payloadJson = rs.getString("payload");
            String messageTypeStr = rs.getString("message_type");
            String originalMessageId = rs.getString("original_message_id");
            String statusStr = rs.getString("status");
            Instant timestamp = rs.getTimestamp("timestamp").toInstant();

            Object payloadObject = null;
            if (payloadJson != null) {
                try {
                    // TODO: Determine the specific class for payload based on messageType or store class info
                    payloadObject = objectMapper.readValue(payloadJson, Object.class);
                } catch (JsonProcessingException e) {
                    logger.error("Error deserializing message payload for messageId {}: {}", messageId, e.getMessage(), e);
                    // Depending on requirements, might throw, or return message with null/raw payload
                }
            }

            // The 'recipient_id' is not directly in the 'messages' table in our current schema.
            // It's part of the 'conversations' table logic (target_peer_id) or implied.
            // Passing null for recipientId when constructing from 'messages' table row.
            // The service layer can enrich this if necessary.
            String recipientIdFromDb = null; // Or rs.getString("recipient_id") if we add it to the messages table

            return new Message(
                    messageId,
                    conversationId,
                    Message.MessageType.valueOf(messageTypeStr),
                    senderId,
                    recipientIdFromDb, // This is fine as Message constructor accepts null recipientId
                    payloadObject,
                    timestamp,
                    originalMessageId,
                    Message.MessageStatus.valueOf(statusStr)
            );
        };
    }

    @Override
    public Message save(Message message) {
        if (message == null) {
            throw new IllegalArgumentException("Message to save cannot be null.");
        }
        // Message ID should be set by the Message constructor for new messages (UUID.randomUUID().toString())
        // or be present if it's an existing message being loaded/updated.
        if (message.getMessageId() == null) {
           throw new IllegalArgumentException("Message ID cannot be null when saving.");
        }
        if (message.getConversationId() == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null in Message to be saved.");
        }

        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(message.getPayload());
        } catch (JsonProcessingException e) {
            logger.error("Error serializing message payload for save: {}", e.getMessage(), e);
            // Consider a custom unchecked exception
            throw new RuntimeException("Failed to serialize message payload", e);
        }

        String sql = "INSERT INTO messages (message_id, conversation_id, sender_id, payload, message_type, " +
                     "original_message_id, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(message_id) DO UPDATE SET " +
                     "conversation_id = excluded.conversation_id, " +
                     "sender_id = excluded.sender_id, " +
                     "payload = excluded.payload, " +
                     "message_type = excluded.message_type, " +
                     "original_message_id = excluded.original_message_id, " +
                     "status = excluded.status, " +
                     "timestamp = excluded.timestamp";

        try {
            jdbcTemplate.update(sql,
                    message.getMessageId(),
                    message.getConversationId(), // Now correctly uses getConversationId()
                    message.getSenderId(),
                    payloadJson,
                    message.getType().name(),
                    message.getOriginalMessageId(),
                    message.getStatus() != null ? message.getStatus().name() : Message.MessageStatus.PENDING.name(),
                    Timestamp.from(message.getTimestamp()));
            return message;
        } catch (DataAccessException e) {
            logger.error("Error saving message with ID {}: {}", message.getMessageId(), e.getMessage(), e);
            // Depending on policy, rethrow as custom exception or return null/Optional.empty()
            throw new RuntimeException("Failed to save message", e);
        }
    }

    @Override
    public Optional<Message> findById(String messageId) {
        if (messageId == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM messages WHERE message_id = ?";
        try {
            Message message = jdbcTemplate.queryForObject(sql, new Object[]{messageId}, messageRowMapper());
            return Optional.ofNullable(message);
        } catch (EmptyResultDataAccessException e) {
            logger.debug("No message found with ID: {}", messageId);
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding message by ID {}: {}", messageId, e.getMessage(), e);
            return Optional.empty(); // Or rethrow
        }
    }

    @Override
    public boolean updateMessageStatus(String messageId, Message.MessageStatus newStatus) {
        if (messageId == null || newStatus == null) {
            throw new IllegalArgumentException("Message ID and new status cannot be null for update.");
        }
        String sql = "UPDATE messages SET status = ? WHERE message_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, newStatus.name(), messageId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating status for message ID {}: {}", messageId, e.getMessage(), e);
            return false; // Or rethrow
        }
    }

    @Override
    public List<Message> findByConversationIdOrderByTimestampDesc(String conversationId, int limit, int offset) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null.");
        }
        String sql = "SELECT * FROM messages WHERE conversation_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?";
        try {
            return jdbcTemplate.query(sql, new Object[]{conversationId, limit, offset}, messageRowMapper());
        } catch (DataAccessException e) {
            logger.error("Error finding messages by conversation ID {}: {}", conversationId, e.getMessage(), e);
            return List.of(); // Or rethrow
        }
    }

    @Override
    public List<Message> findByConversationIdAndTimestampAfter(String conversationId, Instant afterTimestamp) {
        if (conversationId == null || afterTimestamp == null) {
            throw new IllegalArgumentException("Conversation ID and timestamp cannot be null.");
        }
        String sql = "SELECT * FROM messages WHERE conversation_id = ? AND timestamp > ? ORDER BY timestamp ASC";
        try {
            return jdbcTemplate.query(sql, new Object[]{conversationId, Timestamp.from(afterTimestamp)}, messageRowMapper());
        } catch (DataAccessException e) {
            logger.error("Error finding messages by conversation ID {} after {}: {}", conversationId, afterTimestamp, e.getMessage(), e);
            return List.of(); // Or rethrow
        }
    }

    @Override
    public List<Message> findRepliesByOriginalMessageIdOrderByTimestampAsc(String originalMessageId) {
        if (originalMessageId == null) {
            throw new IllegalArgumentException("Original message ID cannot be null.");
        }
        String sql = "SELECT * FROM messages WHERE original_message_id = ? ORDER BY timestamp ASC";
        try {
            return jdbcTemplate.query(sql, new Object[]{originalMessageId}, messageRowMapper());
        } catch (DataAccessException e) {
            logger.error("Error finding replies for original message ID {}: {}", originalMessageId, e.getMessage(), e);
            return List.of(); // Or rethrow
        }
    }

    @Override
    public List<Message> findMessagesByUserIdAndStatus(String userId, Message.MessageStatus status) {
        if (userId == null || status == null) {
            throw new IllegalArgumentException("User ID and status cannot be null.");
        }
        // This query finds messages SENT by the userId with a specific status.
        // For messages RECEIVED by userId, a more complex query involving conversations would be needed.
        String sql = "SELECT * FROM messages WHERE sender_id = ? AND status = ? ORDER BY timestamp DESC";
        try {
            return jdbcTemplate.query(sql, new Object[]{userId, status.name()}, messageRowMapper());
        } catch (DataAccessException e) {
            logger.error("Error finding messages by user ID {} and status {}: {}", userId, status, e.getMessage(), e);
            return List.of(); // Or rethrow
        }
    }

    @Override
    public boolean deleteById(String messageId) {
        if (messageId == null) {
            throw new IllegalArgumentException("Message ID cannot be null for deletion.");
        }
        // Consider implications of foreign key constraints if messages are referenced elsewhere (e.g., conversations.last_message_id)
        // Soft delete (e.g., setting a 'deleted' flag or moving to an archive table) might be safer.
        // For now, performing a hard delete.
        String sql = "DELETE FROM messages WHERE message_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, messageId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting message by ID {}: {}", messageId, e.getMessage(), e);
            return false; // Or rethrow
        }
    }

    @Override
    public long countUnreadMessagesByConversationIdAndUserId(String conversationId, String userId) {
        if (conversationId == null || userId == null) {
            throw new IllegalArgumentException("Conversation ID and User ID cannot be null.");
        }
        // Counts messages in the conversation NOT sent by the given userId and are not READ.
        String sql = "SELECT COUNT(*) FROM messages " +
                     "WHERE conversation_id = ? AND sender_id != ? AND status != ?";
        try {
            Long count = jdbcTemplate.queryForObject(sql, new Object[]{conversationId, userId, Message.MessageStatus.READ.name()}, Long.class);
            return count != null ? count : 0L;
        } catch (DataAccessException e) {
            logger.error("Error counting unread messages for conversation {} and user {}: {}", conversationId, userId, e.getMessage(), e);
            return 0L; // Or rethrow
        }
    }

    @Override
    public int markMessagesAsRead(String conversationId, String userId) {
        if (conversationId == null || userId == null) {
            throw new IllegalArgumentException("Conversation ID and User ID cannot be null.");
        }
        // Marks messages in the conversation as READ if they were not sent by the given userId
        // and are not already READ.
        String sql = "UPDATE messages SET status = ? " +
                     "WHERE conversation_id = ? AND sender_id != ? AND status != ?";
        try {
            return jdbcTemplate.update(sql, Message.MessageStatus.READ.name(), conversationId, userId, Message.MessageStatus.READ.name());
        } catch (DataAccessException e) {
            logger.error("Error marking messages as read for conversation {} and user {}: {}", conversationId, userId, e.getMessage(), e);
            return 0; // Or rethrow
        }
    }
}

