package com.couchat.repository.impl;

import com.couchat.repository.UserRepository;
import com.couchat.user.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * JDBC implementation of the {@link UserRepository} interface.
 * Handles database operations for {@link User} entities using JdbcTemplate.
 */
@Repository
public class JdbcUserRepository implements UserRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcUserRepository.class);
    private final JdbcTemplate jdbcTemplate;

    /**
     * RowMapper to map a ResultSet row to a {@link User} object.
     */
    private final RowMapper<User> userRowMapper = (rs, rowNum) -> new User(
            rs.getString("user_id"),
            rs.getString("username"),
            rs.getString("password_hash"),
            rs.getString("public_key"),
            rs.getString("oauth_provider"),
            rs.getString("oauth_id"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("last_seen_at") != null ? rs.getTimestamp("last_seen_at").toInstant() : null
    );

    @Autowired
    public JdbcUserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public User save(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User to save cannot be null.");
        }
        if (user.getUserId() == null) {
            throw new IllegalArgumentException("User ID cannot be null when saving an existing user or if ID generation is manual.");
        }

        // Upsert logic: Insert or Update on conflict (based on user_id)
        String sql = "INSERT INTO users (user_id, username, password_hash, public_key, oauth_provider, oauth_id, created_at, last_seen_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(user_id) DO UPDATE SET " +
                     "username = excluded.username, " +
                     "password_hash = excluded.password_hash, " +
                     "public_key = excluded.public_key, " +
                     "oauth_provider = excluded.oauth_provider, " +
                     "oauth_id = excluded.oauth_id, " +
                     "last_seen_at = excluded.last_seen_at";
        try {
            jdbcTemplate.update(sql,
                    user.getUserId(),
                    user.getUsername(),
                    user.getPasswordHash(),
                    user.getPublicKey(),
                    user.getOauthProvider(),
                    user.getOauthId(),
                    Timestamp.from(user.getCreatedAt()),
                    user.getLastSeenAt() != null ? Timestamp.from(user.getLastSeenAt()) : null
            );
            return user;
        } catch (DataAccessException e) {
            logger.error("Error saving user with ID {}: {}", user.getUserId(), e.getMessage(), e);
            throw new RuntimeException("Failed to save user", e); // Or a custom persistence exception
        }
    }

    @Override
    public Optional<User> findById(String userId) {
        if (userId == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM users WHERE user_id = ?";
        try {
            User user = jdbcTemplate.queryForObject(sql, new Object[]{userId}, userRowMapper);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            logger.debug("No user found with ID: {}", userId);
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding user by ID {}: {}", userId, e.getMessage(), e);
            return Optional.empty(); // Or rethrow
        }
    }

    @Override
    public Optional<User> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM users WHERE username = ?";
        try {
            User user = jdbcTemplate.queryForObject(sql, new Object[]{username}, userRowMapper);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            logger.debug("No user found with username: {}", username);
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding user by username {}: {}", username, e.getMessage(), e);
            return Optional.empty(); // Or rethrow
        }
    }

    @Override
    public Optional<User> findByOAuthProviderAndId(String oauthProvider, String oauthId) {
        if (oauthProvider == null || oauthId == null) {
            return Optional.empty();
        }
        String sql = "SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?";
        try {
            User user = jdbcTemplate.queryForObject(sql, new Object[]{oauthProvider, oauthId}, userRowMapper);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            logger.debug("No user found with OAuth provider {} and ID: {}", oauthProvider, oauthId);
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding user by OAuth provider {} and ID {}: {}", oauthProvider, oauthId, e.getMessage(), e);
            return Optional.empty(); // Or rethrow
        }
    }

    @Override
    public boolean deleteById(String userId) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null for deletion.");
        }
        // Foreign key constraints in other tables (devices, group_members, messages, groups.created_by)
        // are set to ON DELETE CASCADE or ON DELETE SET NULL where appropriate for users.
        // So, direct deletion here should be handled by the DB if schema is set up correctly.
        String sql = "DELETE FROM users WHERE user_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, userId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting user by ID {}: {}", userId, e.getMessage(), e);
            return false; // Or rethrow
        }
    }

    @Override
    public List<User> findAll() {
        String sql = "SELECT * FROM users ORDER BY username ASC"; // Added default ordering
        try {
            return jdbcTemplate.query(sql, userRowMapper);
        } catch (DataAccessException e) {
            logger.error("Error finding all users: {}", e.getMessage(), e);
            return List.of(); // Or rethrow
        }
    }

    @Override
    public boolean updateLastSeenAt(String userId, Instant lastSeenAt) {
        if (userId == null || lastSeenAt == null) {
            throw new IllegalArgumentException("User ID and lastSeenAt cannot be null.");
        }
        String sql = "UPDATE users SET last_seen_at = ? WHERE user_id = ?";
        try {
            int rowsAffected = jdbcTemplate.update(sql, Timestamp.from(lastSeenAt), userId);
            return rowsAffected > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating last_seen_at for user ID {}: {}", userId, e.getMessage(), e);
            return false; // Or rethrow
        }
    }
}

