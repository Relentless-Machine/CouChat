package com.couchat.group.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a group chat in the CouChat system.
 * This class maps to the 'groups' table in the database.
 */
public class Group {

    private final String groupId;     // Primary Key, UUID
    private String groupName;
    private final String createdBy;   // user_id of the creator
    private final Instant createdAt;
    private Instant updatedAt;

    /**
     * Constructor for creating a new group.
     *
     * @param groupName The name of the group. Must not be null.
     * @param createdBy The user ID of the creator. Must not be null.
     */
    public Group(String groupName, String createdBy) {
        this.groupId = UUID.randomUUID().toString();
        this.groupName = Objects.requireNonNull(groupName, "Group name cannot be null.");
        this.createdBy = Objects.requireNonNull(createdBy, "Creator user ID cannot be null.");
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    /**
     * Constructor for loading an existing group from the database.
     *
     * @param groupId The unique ID of the group.
     * @param groupName The name of the group.
     * @param createdBy The user ID of the creator.
     * @param createdAt Timestamp of creation.
     * @param updatedAt Timestamp of the last update.
     */
    public Group(String groupId, String groupName, String createdBy, Instant createdAt, Instant updatedAt) {
        this.groupId = Objects.requireNonNull(groupId, "Group ID cannot be null.");
        this.groupName = Objects.requireNonNull(groupName, "Group name cannot be null.");
        this.createdBy = Objects.requireNonNull(createdBy, "Creator user ID cannot be null.");
        this.createdAt = Objects.requireNonNull(createdAt, "Creation timestamp cannot be null.");
        this.updatedAt = Objects.requireNonNull(updatedAt, "Update timestamp cannot be null.");
    }

    // Getters
    public String getGroupId() {
        return groupId;
    }

    public String getGroupName() {
        return groupName;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    // Setters for mutable fields
    public void setGroupName(String groupName) {
        this.groupName = Objects.requireNonNull(groupName, "Group name cannot be null.");
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = Objects.requireNonNull(updatedAt, "Update timestamp cannot be null.");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group group = (Group) o;
        return Objects.equals(groupId, group.groupId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupId);
    }

    @Override
    public String toString() {
        return "Group{" +
                "groupId='" + groupId + '\'' +
                ", groupName='" + groupName + '\'' +
                ", createdBy='" + createdBy + '\'' +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}

