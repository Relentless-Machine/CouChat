package com.couchat.repository.impl;

import com.couchat.conversation.model.Conversation;
import com.couchat.repository.ConversationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * JDBC implementation of the {@link ConversationRepository} interface.
 */
@Repository
public class JdbcConversationRepository implements ConversationRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcConversationRepository.class);
    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<Conversation> conversationRowMapper = (rs, rowNum) -> new Conversation(
            rs.getString("conversation_id"),
            rs.getString("target_peer_id"),
            Conversation.ConversationType.valueOf(rs.getString("conversation_type")),
            rs.getString("last_message_id"),
            rs.getTimestamp("last_message_timestamp") != null ? rs.getTimestamp("last_message_timestamp").toInstant() : null,
            rs.getInt("unread_count"),
            rs.getBoolean("is_archived"),
            rs.getBoolean("is_muted"),
            rs.getBoolean("is_pinned"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant()
    );

    @Autowired
    public JdbcConversationRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public Conversation save(Conversation conversation) {
        if (conversation == null) {
            throw new IllegalArgumentException("Conversation to save cannot be null.");
        }
        // Upsert logic
        String sql = "INSERT INTO conversations (conversation_id, target_peer_id, conversation_type, last_message_id, " +
                     "last_message_timestamp, unread_count, is_archived, is_muted, is_pinned, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(conversation_id) DO UPDATE SET " +
                     "target_peer_id = excluded.target_peer_id, " +
                     "conversation_type = excluded.conversation_type, " +
                     "last_message_id = excluded.last_message_id, " +
                     "last_message_timestamp = excluded.last_message_timestamp, " +
                     "unread_count = excluded.unread_count, " +
                     "is_archived = excluded.is_archived, " +
                     "is_muted = excluded.is_muted, " +
                     "is_pinned = excluded.is_pinned, " +
                     "updated_at = excluded.updated_at";
        try {
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
                    Timestamp.from(conversation.getUpdatedAt())
            );
            return conversation;
        } catch (DataAccessException e) {
            logger.error("Error saving conversation with ID {}: {}", conversation.getConversationId(), e.getMessage(), e);
            throw new RuntimeException("Failed to save conversation", e);
        }
    }

    @Override
    public Optional<Conversation> findById(String conversationId) {
        if (conversationId == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM conversations WHERE conversation_id = ?";
        try {
            Conversation conv = jdbcTemplate.queryForObject(sql, new Object[]{conversationId}, conversationRowMapper);
            return Optional.ofNullable(conv);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding conversation by ID {}: {}", conversationId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<Conversation> findByTargetPeerIdAndType(String targetPeerId, Conversation.ConversationType type) {
        if (targetPeerId == null || type == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM conversations WHERE target_peer_id = ? AND conversation_type = ?";
        try {
            Conversation conv = jdbcTemplate.queryForObject(sql, new Object[]{targetPeerId, type.name()}, conversationRowMapper);
            return Optional.ofNullable(conv);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding conversation by targetPeerId {} and type {}: {}", targetPeerId, type, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public List<Conversation> findAllByUserId(String userId, int limit, int offset) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null.");
        }
        // This query retrieves individual chats where the user is the target_peer_id
        // OR group chats where the user is a member of the group (target_peer_id for group chats is group_id)
        // It assumes that for individual chats, a conversation entry exists with the current user as target_peer_id
        // if the other user initiated it, or the service layer creates conversations from both perspectives.
        // A more robust way for individual chats might involve checking if target_peer_id = userId OR if a related conversation exists.
        // For simplicity, this query focuses on direct matches or group membership.
        String sql = "SELECT c.* FROM conversations c " +
                     "LEFT JOIN group_members gm ON c.target_peer_id = gm.group_id AND c.conversation_type = 'GROUP' " +
                     "WHERE (c.conversation_type = 'INDIVIDUAL' AND c.target_peer_id = ?) " +
                     "OR (c.conversation_type = 'GROUP' AND gm.user_id = ?) " +
                     "ORDER BY c.updated_at DESC LIMIT ? OFFSET ?";
        try {
            return jdbcTemplate.query(sql, new Object[]{userId, userId, limit, offset}, conversationRowMapper);
        } catch (DataAccessException e) {
            logger.error("Error finding conversations for user ID {}: {}", userId, e.getMessage(), e);
            return List.of();
        }
    }

    @Override
    public boolean deleteById(String conversationId) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null for deletion.");
        }
        // Deleting a conversation might also require deleting associated messages or handling them.
        // The messages table has a FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id).
        // If ON DELETE CASCADE is not set for that FK, this delete will fail if messages exist.
        // Current db_schema.sql for messages.conversation_id does NOT have ON DELETE CASCADE.
        // Recommendation: Add ON DELETE CASCADE to messages.conversation_id FK or handle message deletion here/in service.
        logger.warn("Deleting conversation {}. Ensure messages are handled (e.g., ON DELETE CASCADE on messages.conversation_id FK).");
        String sql = "DELETE FROM conversations WHERE conversation_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, conversationId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting conversation by ID {}: {}", conversationId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateLastMessageDetails(String conversationId, String lastMessageId, Instant lastMessageTimestamp) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null.");
        }
        String sql = "UPDATE conversations SET last_message_id = ?, last_message_timestamp = ?, updated_at = CURRENT_TIMESTAMP WHERE conversation_id = ?";
        try {
            // Handle null lastMessageId by setting it to NULL in the database
            Object lastMessageIdArg = lastMessageId;
            int[] argTypes = new int[]{Types.VARCHAR, Types.TIMESTAMP, Types.VARCHAR};
            if (lastMessageId == null) {
                lastMessageIdArg = null;
                argTypes[0] = Types.NULL;
            }

            int rowsAffected = jdbcTemplate.update(sql,
                ps -> {
                    if (lastMessageId != null) {
                        ps.setString(1, lastMessageId);
                    } else {
                        ps.setNull(1, Types.VARCHAR);
                    }
                    if (lastMessageTimestamp != null) {
                        ps.setTimestamp(2, Timestamp.from(lastMessageTimestamp));
                    } else {
                        ps.setNull(2, Types.TIMESTAMP);
                    }
                    ps.setString(3, conversationId);
                }
            );
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating last message details for conversation ID {}: {}", conversationId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateUnreadCount(String conversationId, int unreadCount) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null.");
        }
         if (unreadCount < 0) {
            throw new IllegalArgumentException("Unread count cannot be negative.");
        }
        String sql = "UPDATE conversations SET unread_count = ?, updated_at = CURRENT_TIMESTAMP WHERE conversation_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, unreadCount, conversationId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating unread count for conversation ID {}: {}", conversationId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateArchivedStatus(String conversationId, boolean isArchived) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null.");
        }
        String sql = "UPDATE conversations SET is_archived = ?, updated_at = CURRENT_TIMESTAMP WHERE conversation_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, isArchived, conversationId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating archived status for conversation ID {}: {}", conversationId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateMutedStatus(String conversationId, boolean isMuted) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null.");
        }
        String sql = "UPDATE conversations SET is_muted = ?, updated_at = CURRENT_TIMESTAMP WHERE conversation_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, isMuted, conversationId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating muted status for conversation ID {}: {}", conversationId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updatePinnedStatus(String conversationId, boolean isPinned) {
        if (conversationId == null) {
            throw new IllegalArgumentException("Conversation ID cannot be null.");
        }
        String sql = "UPDATE conversations SET is_pinned = ?, updated_at = CURRENT_TIMESTAMP WHERE conversation_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, isPinned, conversationId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating pinned status for conversation ID {}: {}", conversationId, e.getMessage(), e);
            return false;
        }
    }
}

