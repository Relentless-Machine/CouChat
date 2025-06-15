// filepath: F:/Git/CouChat/src/main/java/com/couchat/repository/impl/JdbcConversationRepository.java
package com.couchat.repository.impl;

import com.couchat.conversation.model.Conversation;
import com.couchat.conversation.model.Conversation.ConversationType;
import com.couchat.repository.ConversationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public class JdbcConversationRepository implements ConversationRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcConversationRepository.class);
    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public JdbcConversationRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    private RowMapper<Conversation> conversationRowMapper() {
        return (rs, rowNum) -> new Conversation(
                rs.getString("conversation_id"),
                rs.getString("target_peer_id"),
                ConversationType.valueOf(rs.getString("conversation_type")),
                rs.getString("last_message_id"),
                rs.getTimestamp("last_message_timestamp") != null ? rs.getTimestamp("last_message_timestamp").toInstant() : null,
                rs.getInt("unread_count"),
                rs.getBoolean("is_archived"),
                rs.getBoolean("is_muted"),
                rs.getBoolean("is_pinned"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toInstant() : null
        );
    }

    @Override
    public Conversation save(Conversation conversation) {
        Optional<Conversation> existing = findById(conversation.getConversationId());
        if (existing.isPresent()) {
            // Update
            String sql = "UPDATE conversations SET target_peer_id = ?, conversation_type = ?, " +
                         "last_message_id = ?, last_message_timestamp = ?, unread_count = ?, " +
                         "is_archived = ?, is_muted = ?, is_pinned = ?, updated_at = ? " +
                         "WHERE conversation_id = ?";
            jdbcTemplate.update(sql,
                    conversation.getTargetPeerId(),
                    conversation.getConversationType().name(),
                    conversation.getLastMessageId(),
                    conversation.getLastMessageTimestamp() != null ? Timestamp.from(conversation.getLastMessageTimestamp()) : null,
                    conversation.getUnreadCount(),
                    conversation.isArchived(),
                    conversation.isMuted(),
                    conversation.isPinned(),
                    Timestamp.from(conversation.getUpdatedAt() != null ? conversation.getUpdatedAt() : Instant.now()),
                    conversation.getConversationId());
            logger.debug("Updated conversation: {}", conversation.getConversationId());
        } else {
            // Insert
            String sql = "INSERT INTO conversations (conversation_id, target_peer_id, conversation_type, " +
                         "last_message_id, last_message_timestamp, unread_count, is_archived, is_muted, " +
                         "is_pinned, created_at, updated_at) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            jdbcTemplate.update(sql,
                    conversation.getConversationId(),
                    conversation.getTargetPeerId(),
                    conversation.getConversationType().name(),
                    conversation.getLastMessageId(),
                    conversation.getLastMessageTimestamp() != null ? Timestamp.from(conversation.getLastMessageTimestamp()) : null,
                    conversation.getUnreadCount(),
                    conversation.isArchived(),
                    conversation.isMuted(),
                    conversation.isPinned(),
                    Timestamp.from(conversation.getCreatedAt()),
                    Timestamp.from(conversation.getUpdatedAt() != null ? conversation.getUpdatedAt() : Instant.now()));
            logger.debug("Inserted new conversation: {}", conversation.getConversationId());
        }
        return conversation;
    }

    @Override
    public Optional<Conversation> findById(String conversationId) {
        String sql = "SELECT * FROM conversations WHERE conversation_id = ?";
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject(sql, conversationRowMapper(), conversationId));
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    @Override
    public List<Conversation> findAllByUserId(String userId, int limit, int offset) {
        logger.warn("findAllByUserId in JdbcConversationRepository is a simplified placeholder and may need a more complex query for group chats.");
        String sql = "SELECT * FROM conversations WHERE target_peer_id = ? OR conversation_id IN (SELECT group_id FROM group_members WHERE user_id = ?) ORDER BY updated_at DESC LIMIT ? OFFSET ?";
        return jdbcTemplate.query(sql, conversationRowMapper(), userId, userId, limit, offset);
    }

    @Override
    public Optional<Conversation> findByTargetPeerIdAndType(String targetPeerOrGroupId, ConversationType type) {
        String sql = "SELECT * FROM conversations WHERE target_peer_id = ? AND conversation_type = ?";
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject(sql, conversationRowMapper(), targetPeerOrGroupId, type.name()));
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    @Override
    public void updateLastMessageDetails(String conversationId, String lastMessageId, Instant lastMessageTimestamp) {
        String sql = "UPDATE conversations SET last_message_id = ?, last_message_timestamp = ?, updated_at = ? WHERE conversation_id = ?";
        int rows = jdbcTemplate.update(sql, lastMessageId,
                                       lastMessageTimestamp != null ? Timestamp.from(lastMessageTimestamp) : null,
                                       Timestamp.from(Instant.now()),
                                       conversationId);
        if (rows == 0) {
            logger.warn("No conversation found with ID {} to update last message details.", conversationId);
        }
    }

    @Override
    public int resetUnreadCount(String conversationId, String userId) {
        String sql = "UPDATE conversations SET unread_count = 0, updated_at = ? WHERE conversation_id = ?";
        logger.info("Resetting unread count for conversation {} (user {} context - simplified)", conversationId, userId);
        return jdbcTemplate.update(sql, Timestamp.from(Instant.now()), conversationId);
    }

    @Override
    public int decrementUnreadCount(String conversationId, String userId) {
        String sql = "UPDATE conversations SET unread_count = CASE WHEN unread_count > 0 THEN unread_count - 1 ELSE 0 END, updated_at = ? WHERE conversation_id = ?";
        logger.info("Decrementing unread count for conversation {} (user {} context - simplified)", conversationId, userId);
        return jdbcTemplate.update(sql, Timestamp.from(Instant.now()), conversationId);
    }

    @Override
    public int incrementUnreadCount(String conversationId, String userId) {
        String sql = "UPDATE conversations SET unread_count = unread_count + 1, updated_at = ? WHERE conversation_id = ?";
        logger.info("Incrementing unread count for conversation {} (user {} context - simplified)", conversationId, userId);
        return jdbcTemplate.update(sql, Timestamp.from(Instant.now()), conversationId);
    }

    @Override
    public int updateArchivedStatus(String conversationId, String userId, boolean isArchived) {
        String sql = "UPDATE conversations SET is_archived = ?, updated_at = ? WHERE conversation_id = ?";
        logger.info("Updating archived status for conversation {} to {} (user {} context - simplified)", conversationId, isArchived, userId);
        return jdbcTemplate.update(sql, isArchived, Timestamp.from(Instant.now()), conversationId);
    }

    @Override
    public int updateMutedStatus(String conversationId, String userId, boolean isMuted) {
        String sql = "UPDATE conversations SET is_muted = ?, updated_at = ? WHERE conversation_id = ?";
        logger.info("Updating muted status for conversation {} to {} (user {} context - simplified)", conversationId, isMuted, userId);
        return jdbcTemplate.update(sql, isMuted, Timestamp.from(Instant.now()), conversationId);
    }

    @Override
    public int updatePinnedStatus(String conversationId, String userId, boolean isPinned) {
        String sql = "UPDATE conversations SET is_pinned = ?, updated_at = ? WHERE conversation_id = ?";
        logger.info("Updating pinned status for conversation {} to {} (user {} context - simplified)", conversationId, isPinned, userId);
        return jdbcTemplate.update(sql, isPinned, Timestamp.from(Instant.now()), conversationId);
    }

    @Override
    public void deleteById(String conversationId) {
        String sql = "DELETE FROM conversations WHERE conversation_id = ?";
        int rows = jdbcTemplate.update(sql, conversationId);
        if (rows > 0) {
            logger.info("Deleted conversation with ID: {}", conversationId);
        } else {
            logger.warn("No conversation found with ID: {} to delete.", conversationId);
        }
    }
}
