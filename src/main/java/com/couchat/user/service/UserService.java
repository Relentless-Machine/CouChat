package com.couchat.user.service;

import com.couchat.repository.UserRepository;
import com.couchat.user.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Service layer for user-related operations.
 * Provides stub implementations for now.
 */
@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Registers a new user or updates an existing one.
     *
     * @param user The user to register or update.
     * @return The saved user.
     */
    public User registerOrUpdateUser(User user) {
        logger.info("UserService.registerOrUpdateUser called for userId: {}", user.getUserId());
        // Basic validation
        if (user.getUsername() == null || user.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        // In a real scenario, add password hashing here if local auth, etc.
        return userRepository.save(user);
    }

    /**
     * Finds a user by their ID.
     *
     * @param userId The ID of the user.
     * @return An Optional containing the user if found.
     */
    public Optional<User> findUserById(String userId) {
        logger.info("UserService.findUserById called for userId: {}", userId);
        return userRepository.findById(userId);
    }

    /**
     * Finds a user by their username.
     *
     * @param username The username.
     * @return An Optional containing the user if found.
     */
    public Optional<User> findUserByUsername(String username) {
        logger.info("UserService.findUserByUsername called for username: {}", username);
        return userRepository.findByUsername(username);
    }

    /**
     * Finds a user by OAuth provider details.
     *
     * @param provider The OAuth provider.
     * @param oauthId The OAuth ID.
     * @return An Optional containing the user if found.
     */
    public Optional<User> findUserByOAuthDetails(String provider, String oauthId) {
        logger.info("UserService.findUserByOAuthDetails called for provider: {}, oauthId: {}", provider, oauthId);
        return userRepository.findByOAuthProviderAndId(provider, oauthId);
    }

    /**
     * Deletes a user by their ID.
     *
     * @param userId The ID of the user to delete.
     * @return true if deletion was successful.
     */
    public boolean deleteUser(String userId) {
        logger.info("UserService.deleteUser called for userId: {}", userId);
        return userRepository.deleteById(userId);
    }

    /**
     * Retrieves all users.
     * Note: Use with caution in production; consider pagination.
     *
     * @return A list of all users.
     */
    public List<User> getAllUsers() {
        logger.info("UserService.getAllUsers called.");
        return userRepository.findAll();
    }

    /**
     * Updates the last seen timestamp for a user.
     *
     * @param userId The user ID.
     */
    public void updateUserLastSeen(String userId) {
        logger.info("UserService.updateUserLastSeen called for userId: {}", userId);
        userRepository.updateLastSeenAt(userId, Instant.now());
    }
}

