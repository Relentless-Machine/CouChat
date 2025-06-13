package com.couchat.user.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a user in the CouChat system.
 * This class maps to the 'users' table in the database.
 */
public class User {

    private final String userId;          // Primary Key, UUID
    private String username;              // Unique display name
    private String passwordHash;          // Hashed password for local authentication
    private String publicKey;             // User's main RSA public key (string format)
    private String oauthProvider;         // OAuth provider (e.g., GOOGLE, MICROSOFT)
    private String oauthId;               // User's unique ID from the OAuth provider
    private final Instant createdAt;      // Timestamp of user creation
    private Instant lastSeenAt;           // Timestamp of user's last activity

    /**
     * Constructor for creating a new user instance before saving to the database.
     * Generates a new userId and sets the current createdAt timestamp.
     *
     * @param username The user's chosen display name. Must not be null.
     */
    public User(String username) {
        this.userId = UUID.randomUUID().toString();
        this.username = Objects.requireNonNull(username, "Username cannot be null.");
        this.createdAt = Instant.now();
        this.lastSeenAt = this.createdAt; // Initially, last seen is creation time
    }

    /**
     * Constructor for loading an existing user from the database or for full manual creation.
     *
     * @param userId The unique ID of the user.
     * @param username The user's display name.
     * @param passwordHash The hashed password (can be null if using OAuth only).
     * @param publicKey The user's RSA public key (can be null).
     * @param oauthProvider The OAuth provider name (can be null).
     * @param oauthId The user's ID from the OAuth provider (can be null).
     * @param createdAt The timestamp when the user was created.
     * @param lastSeenAt The timestamp of the user's last activity.
     */
    public User(String userId, String username, String passwordHash, String publicKey,
                String oauthProvider, String oauthId, Instant createdAt, Instant lastSeenAt) {
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null.");
        this.username = Objects.requireNonNull(username, "Username cannot be null.");
        this.passwordHash = passwordHash;
        this.publicKey = publicKey;
        this.oauthProvider = oauthProvider;
        this.oauthId = oauthId;
        this.createdAt = Objects.requireNonNull(createdAt, "Creation timestamp cannot be null.");
        this.lastSeenAt = lastSeenAt;
    }

    // Getters
    public String getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getOauthProvider() {
        return oauthProvider;
    }

    public String getOauthId() {
        return oauthId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    // Setters for mutable fields
    public void setUsername(String username) {
        this.username = Objects.requireNonNull(username, "Username cannot be null.");
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public void setOauthProvider(String oauthProvider) {
        this.oauthProvider = oauthProvider;
    }

    public void setOauthId(String oauthId) {
        this.oauthId = oauthId;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    @Override
    public String toString() {
        return "User{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", publicKey='" + (publicKey != null ? publicKey.substring(0, Math.min(publicKey.length(), 10)) + "..." : "null") + '\'' +
                ", oauthProvider='" + oauthProvider + '\'' +
                ", oauthId='" + oauthId + '\'' +
                ", createdAt=" + createdAt +
                ", lastSeenAt=" + lastSeenAt +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(userId, user.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }
}

