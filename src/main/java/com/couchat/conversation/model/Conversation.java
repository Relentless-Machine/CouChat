package com.couchat.conversation.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a conversation in the CouChat system.
 * A conversation can be between two users (INDIVIDUAL) or a group (GROUP).
 * This class maps to the 'conversations' table in the database.
 */
public class Conversation {

    private final String conversationId;    // Primary Key, UUID
    private String targetPeerId;          // If INDIVIDUAL, other user_id. If GROUP, group_id.
    private ConversationType conversationType; // INDIVIDUAL or GROUP
    private String lastMessageId;         // FK to messages.message_id
    private Instant lastMessageTimestamp; // Denormalized for sorting conversations
    private int unreadCount;
    private boolean isArchived;
    private boolean isMuted;
    private boolean isPinned;
    private final Instant createdAt;
    private Instant updatedAt;

    public enum ConversationType {
        INDIVIDUAL,
        GROUP
    }

    /**
     * Constructor for creating a new conversation.
     *
     * @param targetPeerId The ID of the other peer (user or group).
     * @param conversationType The type of the conversation.
     */
    public Conversation(String targetPeerId, ConversationType conversationType) {
        this.conversationId = UUID.randomUUID().toString();
        this.targetPeerId = Objects.requireNonNull(targetPeerId, "Target peer ID cannot be null.");
        this.conversationType = Objects.requireNonNull(conversationType, "Conversation type cannot be null.");
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
        this.unreadCount = 0;
        this.isArchived = false;
        this.isMuted = false;
        this.isPinned = false;
    }

    /**
     * Constructor for loading an existing conversation from the database.
     *
     * @param conversationId The unique ID of the conversation.
     * @param targetPeerId The ID of the target peer (user or group).
     * @param conversationType The type of the conversation.
     * @param lastMessageId The ID of the last message in this conversation (can be null).
     * @param lastMessageTimestamp Timestamp of the last message (can be null).
     * @param unreadCount Number of unread messages for the current user.
     * @param isArchived Whether the conversation is archived.
     * @param isMuted Whether the conversation is muted.
     * @param isPinned Whether the conversation is pinned.
     * @param createdAt Timestamp of creation.
     * @param updatedAt Timestamp of the last update.
     */
    public Conversation(String conversationId, String targetPeerId, ConversationType conversationType,
                        String lastMessageId, Instant lastMessageTimestamp, int unreadCount,
                        boolean isArchived, boolean isMuted, boolean isPinned,
                        Instant createdAt, Instant updatedAt) {
        this.conversationId = Objects.requireNonNull(conversationId, "Conversation ID cannot be null.");
        this.targetPeerId = Objects.requireNonNull(targetPeerId, "Target peer ID cannot be null.");
        this.conversationType = Objects.requireNonNull(conversationType, "Conversation type cannot be null.");
        this.lastMessageId = lastMessageId;
        this.lastMessageTimestamp = lastMessageTimestamp;
        this.unreadCount = unreadCount;
        this.isArchived = isArchived;
        this.isMuted = isMuted;
        this.isPinned = isPinned;
        this.createdAt = Objects.requireNonNull(createdAt, "Creation timestamp cannot be null.");
        this.updatedAt = Objects.requireNonNull(updatedAt, "Update timestamp cannot be null.");
    }

    // Getters
    public String getConversationId() {
        return conversationId;
    }

    public String getTargetPeerId() {
        return targetPeerId;
    }

    public ConversationType getConversationType() {
        return conversationType;
    }

    public String getLastMessageId() {
        return lastMessageId;
    }

    public Instant getLastMessageTimestamp() {
        return lastMessageTimestamp;
    }

    public int getUnreadCount() {
        return unreadCount;
    }

    public boolean isArchived() {
        return isArchived;
    }

    public boolean isMuted() {
        return isMuted;
    }

    public boolean isPinned() {
        return isPinned;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    // Setters for mutable fields
    public void setTargetPeerId(String targetPeerId) {
        this.targetPeerId = Objects.requireNonNull(targetPeerId, "Target peer ID cannot be null.");
    }

    public void setConversationType(ConversationType conversationType) {
        this.conversationType = Objects.requireNonNull(conversationType, "Conversation type cannot be null.");
    }

    public void setLastMessageId(String lastMessageId) {
        this.lastMessageId = lastMessageId;
    }

    public void setLastMessageTimestamp(Instant lastMessageTimestamp) {
        this.lastMessageTimestamp = lastMessageTimestamp;
    }

    public void setUnreadCount(int unreadCount) {
        if (unreadCount < 0) {
            throw new IllegalArgumentException("Unread count cannot be negative.");
        }
        this.unreadCount = unreadCount;
    }

    public void setArchived(boolean archived) {
        isArchived = archived;
    }

    public void setMuted(boolean muted) {
        isMuted = muted;
    }

    public void setPinned(boolean pinned) {
        isPinned = pinned;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = Objects.requireNonNull(updatedAt, "Update timestamp cannot be null.");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Conversation that = (Conversation) o;
        return Objects.equals(conversationId, that.conversationId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(conversationId);
    }

    @Override
    public String toString() {
        return "Conversation{" +
                "conversationId='" + conversationId + '\'' +
                ", targetPeerId='" + targetPeerId + '\'' +
                ", conversationType=" + conversationType +
                ", lastMessageId='" + lastMessageId + '\'' +
                ", lastMessageTimestamp=" + lastMessageTimestamp +
                ", unreadCount=" + unreadCount +
                ", isArchived=" + isArchived +
                ", isMuted=" + isMuted +
                ", isPinned=" + isPinned +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}

