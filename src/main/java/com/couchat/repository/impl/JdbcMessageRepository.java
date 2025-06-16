// filepath: F:/Git/CouChat/src/main/java/com/couchat/repository/impl/JdbcMessageRepository.java
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public class JdbcMessageRepository implements MessageRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcMessageRepository.class);
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper; // For serializing/deserializing payload

    @Autowired
    public JdbcMessageRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    private RowMapper<Message> messageRowMapper() {
      return (rs, rowNum) -> {
        String messageId = rs.getString("message_id");
        String conversationId = rs.getString("conversation_id");
        Message.MessageType type = Message.MessageType.valueOf(rs.getString("message_type"));
        String senderId = rs.getString("sender_id");
        String recipientId = null;
        try {
            recipientId = rs.getString("recipient_id"); // Attempt to get recipient_id
        } catch (SQLException e) {
            // Log if column doesn't exist, but allow to proceed if it's an older schema without it
            // This is a temporary workaround for schema evolution during dev.
            // In production, proper migration is needed.
            if (e.getMessage().toLowerCase().contains("no such column") || e.getMessage().toLowerCase().contains("invalid column name")) {
                logger.warn("Column 'recipient_id' not found in 'messages' table. Proceeding with null. Schema might be outdated.");
            } else {
                throw e; // Re-throw other SQLExceptions
            }
        }


        Object payloadObject;
        String payloadJson = rs.getString("payload");
        try {
            if (payloadJson != null && (payloadJson.startsWith("{") || payloadJson.startsWith("["))) {
                payloadObject = objectMapper.readValue(payloadJson, Object.class);
            } else {
                payloadObject = payloadJson;
            }
        } catch (JsonProcessingException e) {
            logger.error("Error deserializing payload for messageId {}: {}", messageId, e.getMessage());
            payloadObject = payloadJson; // Fallback to raw string
        }

        Instant timestamp = rs.getTimestamp("timestamp").toInstant();
        String originalMessageId = rs.getString("original_message_id");
        Message.MessageStatus status = Message.MessageStatus.valueOf(rs.getString("status"));

        Timestamp readAtTs = rs.getTimestamp("read_at");
        Instant readAt = (readAtTs != null) ? readAtTs.toInstant() : null;

        // Ensure the Message constructor matches the fields being passed
        // If your Message constructor expects recipientId, pass it.
        // If not, adjust the constructor or this call.
        // Assuming Message constructor can handle a null recipientId if the column is missing.
        return new Message(messageId, conversationId, type, senderId, recipientId,
                           payloadObject, timestamp, originalMessageId, status, readAt);
      };
    }

    @Override
    public Message save(Message message) {
        String payloadJson;
        try {
            if (message.getPayload() != null && !(message.getPayload() instanceof String)) {
                 payloadJson = objectMapper.writeValueAsString(message.getPayload());
            } else {
                 payloadJson = (String) message.getPayload();
            }
        } catch (JsonProcessingException e) {
            logger.error("Error serializing payload for message save {}: {}", message.getMessageId(), e.getMessage());
            payloadJson = (message.getPayload() != null) ? message.getPayload().toString() : null;
        }

        Optional<Message> existingMessageOpt = Optional.empty();
        boolean updatedInPlace = false;

        // Try to update status and read_at if it's a READ status update
        if (message.getStatus() == Message.MessageStatus.READ && message.getReadAt() != null) {
             String updateStatusSql = "UPDATE messages SET status = ?, read_at = ? WHERE message_id = ?";
             int rows = jdbcTemplate.update(updateStatusSql, message.getStatus().name(), Timestamp.from(message.getReadAt()), message.getMessageId());
             if (rows > 0) {
                 logger.debug("Updated status/read_at for message ID: {}", message.getMessageId());
                 updatedInPlace = true;
                 return message; // Return after successful in-place update
             }
        }

        // If not a simple status update, or if the status update didn't find the row,
        // proceed with full insert or update.
        if (!updatedInPlace) {
            try {
                // Check if the message exists using a light-weight query before attempting a full findById
                Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM messages WHERE message_id = ?", Integer.class, message.getMessageId());
                if (count != null && count > 0) {
                    existingMessageOpt = Optional.of(message); // Assume message object is what we want to update if it exists
                }
            } catch (DataAccessException e) {
                logger.debug("Error checking existence or message with ID {} not found, will insert.", message.getMessageId());
            }

            if (existingMessageOpt.isPresent()) {
                // Update existing message
                String sql = "UPDATE messages SET conversation_id = ?, sender_id = ?, recipient_id = ?, payload = ?, " +
                             "message_type = ?, original_message_id = ?, status = ?, read_at = ?, timestamp = ? " +
                             "WHERE message_id = ?"; // Corrected SQL, removed extra parenthesis
                jdbcTemplate.update(sql,
                        message.getConversationId(),
                        message.getSenderId(),
                        message.getRecipientId(),
                        payloadJson,
                        message.getType().name(),
                        message.getOriginalMessageId(),
                        message.getStatus().name(),
                        message.getReadAt() != null ? Timestamp.from(message.getReadAt()) : null,
                        Timestamp.from(message.getTimestamp()),
                        message.getMessageId());
                logger.debug("Updated full message with ID: {}", message.getMessageId());
            } else {
                // Insert new message
                String sql = "INSERT INTO messages (message_id, conversation_id, sender_id, recipient_id, payload, " +
                             "message_type, original_message_id, status, read_at, timestamp) " +
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                jdbcTemplate.update(sql,
                        message.getMessageId(),
                        message.getConversationId(),
                        message.getSenderId(),
                        message.getRecipientId(),
                        payloadJson,
                        message.getType().name(),
                        message.getOriginalMessageId(),
                        message.getStatus().name(),
                        message.getReadAt() != null ? Timestamp.from(message.getReadAt()) : null,
                        Timestamp.from(message.getTimestamp()));
                logger.debug("Inserted new message with ID: {}", message.getMessageId());
            }
        }
        return message;
    }

    @Override
    public Optional<Message> findById(String messageId) {
        String sql = "SELECT message_id, conversation_id, sender_id, recipient_id, payload, message_type, original_message_id, status, read_at, timestamp FROM messages WHERE message_id = ?";
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject(sql, new Object[]{messageId}, messageRowMapper()));
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            // Catch cases where 'recipient_id' might be missing if schema is not updated yet
            if (e.getCause() instanceof SQLException &&
                (e.getCause().getMessage().toLowerCase().contains("no such column") || e.getCause().getMessage().toLowerCase().contains("invalid column name"))) {
                logger.warn("findById: Column 'recipient_id' may be missing. Trying query without it for messageId: {}", messageId);
                // Fallback query if recipient_id is problematic (temporary for dev)
                String fallbackSql = "SELECT message_id, conversation_id, sender_id, NULL as recipient_id, payload, message_type, original_message_id, status, read_at, timestamp FROM messages WHERE message_id = ?";
                try {
                    return Optional.ofNullable(jdbcTemplate.queryForObject(fallbackSql, new Object[]{messageId}, messageRowMapper()));
                } catch (org.springframework.dao.EmptyResultDataAccessException ex) {
                    return Optional.empty();
                }
            }
            throw e;
        }
    }

    @Override
    public List<Message> findByConversationIdOrderByTimestampDesc(String conversationId, int limit, int offset) {
        String sql = "SELECT message_id, conversation_id, sender_id, recipient_id, payload, message_type, original_message_id, status, read_at, timestamp FROM messages WHERE conversation_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?";
        try {
            return jdbcTemplate.query(sql, new Object[]{conversationId, limit, offset}, messageRowMapper());
        } catch (DataAccessException e) {
            if (e.getCause() instanceof SQLException &&
                (e.getCause().getMessage().toLowerCase().contains("no such column") || e.getCause().getMessage().toLowerCase().contains("invalid column name"))) {
                 logger.warn("findByConversationIdOrderByTimestampDesc: Column 'recipient_id' may be missing. Trying query without it for conversationId: {}", conversationId);
                // Fallback query if recipient_id is problematic (temporary for dev)
                String fallbackSql = "SELECT message_id, conversation_id, sender_id, NULL as recipient_id, payload, message_type, original_message_id, status, read_at, timestamp FROM messages WHERE conversation_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?";
                return jdbcTemplate.query(fallbackSql, new Object[]{conversationId, limit, offset}, messageRowMapper());
            }
            throw e;
        }
    }

    @Override
    public int markMessagesAsRead(String conversationId, String userId, Instant readAtTimestamp) {
        // This query assumes 'recipient_id' exists and is the correct column to identify the user whose messages are being marked as read.
        String sql = "UPDATE messages SET status = ?, read_at = ? " +
                     "WHERE conversation_id = ? AND recipient_id = ? AND status <> ? AND (read_at IS NULL OR read_at < ?)";
        try {
            int updatedRows = jdbcTemplate.update(sql,
                    Message.MessageStatus.READ.name(),
                    Timestamp.from(readAtTimestamp),
                    conversationId,
                    userId, // This 'userId' is used as 'recipient_id' in the query
                    Message.MessageStatus.READ.name(), // Don't update if already READ
                    Timestamp.from(readAtTimestamp) // Don't update if already read more recently
            );
            if (updatedRows > 0) {
                logger.info("Marked {} messages as READ for user {} in conversation {}", updatedRows, userId, conversationId);
            }
            return updatedRows;
        } catch (DataAccessException e) {
            // Handle potential absence of 'recipient_id' column gracefully
            if (e.getCause() instanceof SQLException &&
                (e.getCause().getMessage().toLowerCase().contains("no such column") || e.getCause().getMessage().toLowerCase().contains("invalid column name"))) {
                logger.warn("markMessagesAsRead: Column 'recipient_id' may be missing. Marking all as read for conversationId: {}", conversationId);
                // Fallback query if recipient_id is problematic (temporary for dev)
                String fallbackSql = "UPDATE messages SET status = ?, read_at = ? " +
                                     "WHERE conversation_id = ? AND status <> ? AND (read_at IS NULL OR read_at < ?)";
                return jdbcTemplate.update(fallbackSql,
                        Message.MessageStatus.READ.name(),
                        Timestamp.from(readAtTimestamp),
                        conversationId,
                        Message.MessageStatus.READ.name(),
                        Timestamp.from(readAtTimestamp)
                );
            }
            throw e;
        }
    }

    @Override
    public void deleteById(String messageId) {
        String sql = "DELETE FROM messages WHERE message_id = ?"; // Corrected: removed trailing quote
        int deletedRows = jdbcTemplate.update(sql, messageId);
        if (deletedRows > 0) {
            logger.info("Deleted message with ID: {}", messageId);
        } else {
            logger.warn("No message found with ID: {} to delete.", messageId);
        }
    }
}
