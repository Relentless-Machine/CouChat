package com.couchat.repository.impl;

import com.couchat.group.model.Group;
import com.couchat.repository.GroupRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * JDBC implementation of the {@link GroupRepository} interface.
 * Provides stub implementations for now to allow application context to load.
 */
@Repository
public class JdbcGroupRepository implements GroupRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcGroupRepository.class);
    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<Group> groupRowMapper = (rs, rowNum) -> new Group(
            rs.getString("group_id"),
            rs.getString("group_name"),
            rs.getString("created_by"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant()
    );

    @Autowired
    public JdbcGroupRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public Group save(Group group) {
        logger.info("JdbcGroupRepository.save called with group: {}", group.getGroupId());
        if (group == null) {
            throw new IllegalArgumentException("Group to save cannot be null.");
        }
        String sql = "INSERT INTO groups (group_id, group_name, created_by, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?) " +
                     "ON CONFLICT(group_id) DO UPDATE SET " +
                     "group_name = excluded.group_name, " +
                     "updated_at = excluded.updated_at";
        try {
            jdbcTemplate.update(sql,
                    group.getGroupId(),
                    group.getGroupName(),
                    group.getCreatedBy(),
                    Timestamp.from(group.getCreatedAt()),
                    Timestamp.from(group.getUpdatedAt())
            );
            return group;
        } catch (DataAccessException e) {
            logger.error("Error saving group with ID {}: {}", group.getGroupId(), e.getMessage(), e);
            throw new RuntimeException("Failed to save group", e);
        }
    }

    @Override
    public Optional<Group> findById(String groupId) {
        logger.info("JdbcGroupRepository.findById called with groupId: {}", groupId);
         if (groupId == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM groups WHERE group_id = ?";
        try {
            Group group = jdbcTemplate.queryForObject(sql, new Object[]{groupId}, groupRowMapper);
            return Optional.ofNullable(group);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding group by ID {}: {}", groupId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public List<Group> findByGroupNameContainingIgnoreCase(String nameSubstring) {
        logger.info("JdbcGroupRepository.findByGroupNameContainingIgnoreCase called with: {}", nameSubstring);
        if (nameSubstring == null) {
            return Collections.emptyList();
        }
        String sql = "SELECT * FROM groups WHERE LOWER(group_name) LIKE LOWER(?)";
        try {
            return jdbcTemplate.query(sql, new Object[]{"%" + nameSubstring + "%"}, groupRowMapper);
        } catch (DataAccessException e) {
            logger.error("Error finding groups by name containing {}: {}", nameSubstring, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public List<Group> findAllByMemberUserId(String userId, int limit, int offset) {
        logger.info("JdbcGroupRepository.findAllByMemberUserId called for user: {} with limit: {}, offset: {}", userId, limit, offset);
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null.");
        }
        String sql = "SELECT g.* FROM groups g " +
                     "JOIN group_members gm ON g.group_id = gm.group_id " +
                     "WHERE gm.user_id = ? ORDER BY g.updated_at DESC LIMIT ? OFFSET ?";
        try {
            return jdbcTemplate.query(sql, new Object[]{userId, limit, offset}, groupRowMapper);
        } catch (DataAccessException e) {
            logger.error("Error finding groups for user ID {}: {}", userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public boolean deleteById(String groupId) {
        logger.info("JdbcGroupRepository.deleteById called with groupId: {}", groupId);
        if (groupId == null) {
            throw new IllegalArgumentException("Group ID cannot be null for deletion.");
        }
        // ON DELETE CASCADE for group_members and conversations referencing this group should handle cleanup.
        String sql = "DELETE FROM groups WHERE group_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, groupId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting group by ID {}: {}", groupId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean addMember(String groupId, String userId, String role) {
        logger.info("JdbcGroupRepository.addMember called for group: {}, user: {}, role: {}", groupId, userId, role);
        if (groupId == null || userId == null || role == null) {
            throw new IllegalArgumentException("Group ID, User ID, and Role cannot be null.");
        }
        String sql = "INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT(group_id, user_id) DO NOTHING";
        try {
            int rowsAffected = jdbcTemplate.update(sql, groupId, userId, role);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error adding member {} to group {}: {}", userId, groupId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean removeMember(String groupId, String userId) {
        logger.info("JdbcGroupRepository.removeMember called for group: {}, user: {}", groupId, userId);
        if (groupId == null || userId == null) {
            throw new IllegalArgumentException("Group ID and User ID cannot be null.");
        }
        String sql = "DELETE FROM group_members WHERE group_id = ? AND user_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, groupId, userId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error removing member {} from group {}: {}", userId, groupId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public List<String> findMemberIdsByGroupId(String groupId) {
        logger.info("JdbcGroupRepository.findMemberIdsByGroupId called for group: {}", groupId);
        if (groupId == null) {
            throw new IllegalArgumentException("Group ID cannot be null.");
        }
        String sql = "SELECT user_id FROM group_members WHERE group_id = ?";
        try {
            return jdbcTemplate.queryForList(sql, String.class, groupId);
        } catch (DataAccessException e) {
            logger.error("Error finding member IDs for group {}: {}", groupId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public boolean updateMemberRole(String groupId, String userId, String newRole) {
        logger.info("JdbcGroupRepository.updateMemberRole called for group: {}, user: {}, newRole: {}", groupId, userId, newRole);
        if (groupId == null || userId == null || newRole == null) {
            throw new IllegalArgumentException("Group ID, User ID, and new Role cannot be null.");
        }
        String sql = "UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, newRole, groupId, userId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating role for member {} in group {}: {}", userId, groupId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean isUserMemberOfGroup(String groupId, String userId) {
        logger.info("JdbcGroupRepository.isUserMemberOfGroup checking for group: {}, user: {}", groupId, userId);
        if (groupId == null || userId == null) {
            return false;
        }
        String sql = "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?";
        try {
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, groupId, userId);
            return count != null && count > 0;
        } catch (DataAccessException e) {
            logger.error("Error checking group membership for group {} and user {}: {}", groupId, userId, e.getMessage(), e);
            return false;
        }
    }
}

