package com.couchat.messaging.model;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a generic message exchanged within the system.
 * This class is designed to be immutable or effectively immutable after creation,
 * especially when loaded from the database.
 */
public class Message implements Serializable {
    @Serial
    private static final long serialVersionUID = 2L; // Updated serialVersionUID

    private final String messageId;
    private final String conversationId; // Added conversationId
    private final MessageType type;
    private final String senderId;
    private final String recipientId; // Kept for context, but conversationId is primary for grouping
    private final Instant timestamp;
    private final Object payload;

    private String originalMessageId; // For replies, can be set post-construction
    private MessageStatus status;     // Can be set post-construction
    private Instant readAt; // Added readAt field

    public enum MessageType {
        TEXT,
        FILE_INFO,
        FILE_CHUNK,
        FILE_TRANSFER_ACCEPTED,
        FILE_TRANSFER_REJECTED,
        FILE_TRANSFER_COMPLETE,
        FILE_TRANSFER_ERROR,
        FILE_TRANSFER_CANCELLED,
        READ_RECEIPT,
        TYPING_INDICATOR,
        SYSTEM_ERROR,
        SYSTEM_INFO
        // Add other types as needed
    }

    public enum MessageStatus {
        PENDING,
        SENT,
        DELIVERED,
        READ,
        FAILED
    }

    /**
     * Constructor for creating a new message before saving to the database.
     * Generates a new messageId and sets the current timestamp.
     *
     * @param conversationId The ID of the conversation this message belongs to.
     * @param type The type of the message.
     * @param senderId The ID of the sender.
     * @param recipientId The ID of the direct recipient (user or group), contextually used with conversationId.
     * @param payload The actual content of the message.
     */
    public Message(String conversationId, MessageType type, String senderId, String recipientId, Object payload) {
        this.messageId = UUID.randomUUID().toString();
        this.conversationId = Objects.requireNonNull(conversationId, "conversationId cannot be null");
        this.type = Objects.requireNonNull(type, "type cannot be null");
        this.senderId = Objects.requireNonNull(senderId, "senderId cannot be null");
        this.recipientId = recipientId; // Can be null if group message or if conversationId is sole identifier
        this.payload = payload; // Payload can be null for certain message types
        this.timestamp = Instant.now();
        this.status = MessageStatus.PENDING; // Default status for new messages
        this.readAt = null; // Initialize readAt
    }

    /**
     * Constructor for loading an existing message from the database or for full manual creation.
     *
     * @param messageId The unique ID of the message.
     * @param conversationId The ID of the conversation this message belongs to.
     * @param type The type of the message.
     * @param senderId The ID of the sender.
     * @param recipientId The ID of the direct recipient (can be null).
     * @param payload The actual content of the message.
     * @param timestamp The time the message was created or sent.
     * @param originalMessageId The ID of the message this is a reply to (can be null).
     * @param status The current status of the message.
     * @param readAt The time the message was read (can be null).
     */
    public Message(String messageId, String conversationId, MessageType type, String senderId, String recipientId,
                   Object payload, Instant timestamp, String originalMessageId, MessageStatus status, Instant readAt) {
        this.messageId = Objects.requireNonNull(messageId, "messageId cannot be null");
        this.conversationId = Objects.requireNonNull(conversationId, "conversationId cannot be null");
        this.type = Objects.requireNonNull(type, "type cannot be null");
        this.senderId = Objects.requireNonNull(senderId, "senderId cannot be null");
        this.recipientId = recipientId;
        this.payload = payload;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp cannot be null");
        this.originalMessageId = originalMessageId;
        this.status = Objects.requireNonNull(status, "status cannot be null");
        this.readAt = readAt;
    }

    // Getters
    public String getMessageId() {
        return messageId;
    }

    public String getConversationId() {
        return conversationId;
    }

    public MessageType getType() {
        return type;
    }

    public String getSenderId() {
        return senderId;
    }

    public String getRecipientId() {
        return recipientId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Object getPayload() {
        return payload;
    }

    public String getOriginalMessageId() {
        return originalMessageId;
    }

    public MessageStatus getStatus() {
        return status;
    }

    public Instant getReadAt() {
        return readAt;
    }

    // Setters
    public void setOriginalMessageId(String originalMessageId) {
        this.originalMessageId = originalMessageId;
    }

    public void setStatus(MessageStatus status) {
        this.status = status;
    }

    public void setReadAt(Instant readAt) {
        this.readAt = readAt;
    }

    // equals, hashCode, toString methods
    @Override
    public String toString() {
        return "Message{" +
                "messageId='" + messageId + "'" +
                ", conversationId='" + conversationId + "'" +
                ", type=" + type +
                ", senderId='" + senderId + "'" +
                ", recipientId='" + recipientId + "'" +
                ", timestamp=" + timestamp +
                ", payload=" + (payload instanceof String && ((String) payload).length() > 50 ? ((String)payload).substring(0,50) + "..." : payload) +
                (originalMessageId != null ? ", originalMessageId='" + originalMessageId + "'" : "") +
                (status != null ? ", status=" + status : "") +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Message message = (Message) o;
        return Objects.equals(messageId, message.messageId); // Primary identity is messageId
    }

    @Override
    public int hashCode() {
        return Objects.hash(messageId); // Primary identity is messageId
    }
}
