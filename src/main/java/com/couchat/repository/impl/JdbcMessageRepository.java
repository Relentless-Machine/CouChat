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

    private RowMapper<Message> messageRowMapper() { // Made it a method returning the instance
      return (rs, rowNum) -> {
        String messageId = rs.getString("message_id");
        String conversationId = rs.getString("conversation_id");
        Message.MessageType type = Message.MessageType.valueOf(rs.getString("message_type"));
        String senderId = rs.getString("sender_id");
        String recipientId = rs.getString("recipient_id");

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

        Optional<Message> existingMessage = Optional.empty(); // findById(message.getMessageId());
        // For simplicity in this restoration, we'll assume new messages are always INSERT
        // and updates (like status/readAt) are handled by specific methods or by re-saving.
        // A robust save would check existence or use UPSERT.

        // If message status indicates it's an update (e.g. READ), try UPDATE first.
        // This is a heuristic. A cleaner way is to have separate create/update methods or rely on caller.
        boolean updated = false;
        if (message.getStatus() == Message.MessageStatus.READ && message.getReadAt() != null) {
             String updateSql = "UPDATE messages SET status = ?, read_at = ? WHERE message_id = ?";
             int rows = jdbcTemplate.update(updateSql, message.getStatus().name(), message.getReadAt(), message.getMessageId());
             if (rows > 0) updated = true;
        }

        if (!updated) { // If not updated (e.g. it was a new message or status wasn't READ)
            // Attempt to find if it exists to prevent duplicate PK errors on simple re-saves
            try {
                existingMessage = findById(message.getMessageId());
            } catch (DataAccessException e) { /* ignore, means it likely doesn't exist */ }

            if (existingMessage.isPresent()) {
                // Update existing message - more comprehensive update
                String sql = "UPDATE messages SET conversation_id = ?, sender_id = ?, recipient_id = ?, payload = ?, " +
                             "message_type = ?, original_message_id = ?, status = ?, read_at = ?, timestamp = ? " +
                             "WHERE message_id = ?";
                jdbcTemplate.update(sql,
                        message.getConversationId(),
                        message.getSenderId(),
                        message.getRecipientId(),
                        payloadJson,
                        message.getType().name(),
                        message.getOriginalMessageId(),
                        message.getStatus().name(),
                        message.getReadAt(),
                        Timestamp.from(message.getTimestamp()),
                        message.getMessageId());
                logger.debug("Updated message with ID: {}", message.getMessageId());
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
                        message.getReadAt(),
                        Timestamp.from(message.getTimestamp()));
                logger.debug("Inserted new message with ID: {}", message.getMessageId());
            }
        }
        return message;
    }

    @Override
    public Optional<Message> findById(String messageId) {
        String sql = "SELECT * FROM messages WHERE message_id = ?";
        try {
            // Pass the RowMapper instance directly
            return Optional.ofNullable(jdbcTemplate.queryForObject(sql, new Object[]{messageId}, messageRowMapper()));
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    @Override
    public List<Message> findByConversationIdOrderByTimestampDesc(String conversationId, int limit, int offset) {
        String sql = "SELECT * FROM messages WHERE conversation_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?";
        // Pass the RowMapper instance directly
        return jdbcTemplate.query(sql, new Object[]{conversationId, limit, offset}, messageRowMapper());
    }

    @Override
    public int markMessagesAsRead(String conversationId, String userId, Instant readAtTimestamp) {
        String sql = "UPDATE messages SET status = ?, read_at = ? " +
                     "WHERE conversation_id = ? AND recipient_id = ? AND status <> ? AND (read_at IS NULL OR read_at < ?)";
        int updatedRows = jdbcTemplate.update(sql,
                Message.MessageStatus.READ.name(),
                Timestamp.from(readAtTimestamp),
                conversationId,
                userId,
                Message.MessageStatus.READ.name(),
                Timestamp.from(readAtTimestamp)
        );
        if (updatedRows > 0) {
            logger.info("Marked {} messages as READ for user {} in conversation {}", updatedRows, userId, conversationId);
        }
        return updatedRows;
    }

    @Override
    public void deleteById(String messageId) {
        String sql = "DELETE FROM messages WHERE message_id = ?";
        int deletedRows = jdbcTemplate.update(sql, messageId);
        if (deletedRows > 0) {
            logger.info("Deleted message with ID: {}", messageId);
        } else {
            logger.warn("No message found with ID: {} to delete.", messageId);
        }
    }
}

