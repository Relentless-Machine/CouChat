package com.couchat.repository;

import com.couchat.user.model.User;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for {@link User} entities.
 * Defines a contract for data access operations related to users.
 */
public interface UserRepository {

    /**
     * Saves a new user or updates an existing one in the database.
     *
     * @param user The {@link User} object to save. Must not be null.
     * @return The saved {@link User} object, potentially with updated fields (e.g., generated ID if not set).
     *         Returns null or throws an exception if saving fails.
     */
    User save(User user);

    /**
     * Finds a user by their unique ID.
     *
     * @param userId The ID of the user to find. Must not be null.
     * @return An {@link Optional} containing the {@link User} if found, or an empty Optional otherwise.
     */
    Optional<User> findById(String userId);

    /**
     * Finds a user by their username.
     * As usernames are unique, this should return at most one user.
     *
     * @param username The username to search for. Must not be null.
     * @return An {@link Optional} containing the {@link User} if found, or an empty Optional otherwise.
     */
    Optional<User> findByUsername(String username);

    /**
     * Finds a user by their OAuth provider and OAuth-specific ID.
     * Useful for identifying users who signed up/in via a third-party service.
     *
     * @param oauthProvider The name of the OAuth provider (e.g., "GOOGLE", "MICROSOFT"). Must not be null.
     * @param oauthId The user's unique ID from that OAuth provider. Must not be null.
     * @return An {@link Optional} containing the {@link User} if found, or an empty Optional otherwise.
     */
    Optional<User> findByOAuthProviderAndId(String oauthProvider, String oauthId);

    /**
     * Deletes a user by their unique ID.
     * Note: Consider the implications of cascading deletes if foreign key constraints are set up accordingly
     * (e.g., deleting a user might delete their devices, group memberships, messages, etc.).
     *
     * @param userId The ID of the user to delete. Must not be null.
     * @return true if the user was deleted successfully, false otherwise.
     */
    boolean deleteById(String userId);

    /**
     * Retrieves all users from the database.
     * Note: For systems with many users, pagination should be implemented.
     * This method is provided for completeness but might be performance-intensive.
     *
     * @return A list of all {@link User} objects. Returns an empty list if no users are found.
     */
    List<User> findAll(); // Consider adding pagination parameters (limit, offset)

    /**
     * Updates the last seen timestamp for a user.
     *
     * @param userId The ID of the user to update. Must not be null.
     * @param lastSeenAt The new last seen timestamp. Must not be null.
     * @return true if the update was successful, false otherwise.
     */
    boolean updateLastSeenAt(String userId, java.time.Instant lastSeenAt);

}

