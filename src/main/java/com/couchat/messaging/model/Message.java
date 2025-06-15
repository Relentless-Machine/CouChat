// filepath: F:/Git/CouChat/src/main/java/com/couchat/messaging/model/Message.java
package com.couchat.messaging.model;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Message implements Serializable {
    @Serial
    private static final long serialVersionUID = 3L; // Increment version due to added field/enum changes

    private final String messageId;
    private final String conversationId;
    private final MessageType type;
    private final String senderId;
    private final String recipientId; // Can be peerId or groupId
    private final Instant timestamp;
    private final Object payload;

    private String originalMessageId; // For replies
    private MessageStatus status;
    private Instant readAt;

    public enum MessageType {
        TEXT,
        FILE_INFO,
        FILE_CHUNK,
        FILE_TRANSFER_ACCEPTED,
        FILE_TRANSFER_REJECTED,
        FILE_TRANSFER_COMPLETE,
        FILE_TRANSFER_ERROR, // For errors during file transfer reported by peers
        FILE_TRANSFER_CANCELLED,
        READ_RECEIPT,
        TYPING_INDICATOR,
        SYSTEM_ERROR, // For general system errors
        SYSTEM_INFO   // For general system information
    }

    public enum MessageStatus {
        PENDING,    // Message created, not yet processed for sending
        SENT,       // Message successfully sent to the P2P layer / network
        DELIVERED,  // Message confirmed delivered to the recipient's device (requires ack from peer)
        READ,       // Message confirmed read by the recipient
        FAILED,     // Message failed to send or process
        INFO,       // Status for informational messages like file transfer control messages (e.g. ACCEPTED, REJECTED)
        ERROR       // Status for error messages (e.g. FILE_TRANSFER_ERROR payload)
    }

    // Constructor for new messages (application-generated ID and timestamp)
    // This constructor might not need @JsonCreator if the one below is the primary for deserialization
    public Message(String conversationId, MessageType type, String senderId, String recipientId, Object payload) {
        this.messageId = UUID.randomUUID().toString();
        this.conversationId = Objects.requireNonNull(conversationId, "conversationId cannot be null");
        this.type = Objects.requireNonNull(type, "type cannot be null");
        this.senderId = Objects.requireNonNull(senderId, "senderId cannot be null");
        this.recipientId = recipientId; // Can be null for group messages if conversationId is the groupId
        this.payload = payload;
        this.timestamp = Instant.now();
        this.status = MessageStatus.PENDING; // Default status
        this.readAt = null;
    }

    // Full constructor (e.g., for loading from DB or when all fields are known)
    @JsonCreator
    public Message(
            @JsonProperty("messageId") String messageId,
            @JsonProperty("conversationId") String conversationId,
            @JsonProperty("type") MessageType type,
            @JsonProperty("senderId") String senderId,
            @JsonProperty("recipientId") String recipientId,
            @JsonProperty("payload") Object payload,
            @JsonProperty("timestamp") Instant timestamp,
            @JsonProperty("originalMessageId") String originalMessageId,
            @JsonProperty("status") MessageStatus status,
            @JsonProperty("readAt") Instant readAt) {
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
    public String getMessageId() { return messageId; }
    public String getConversationId() { return conversationId; }
    public MessageType getType() { return type; }
    public String getSenderId() { return senderId; }
    public String getRecipientId() { return recipientId; }
    public Instant getTimestamp() { return timestamp; }
    public Object getPayload() { return payload; }
    public String getOriginalMessageId() { return originalMessageId; }
    public MessageStatus getStatus() { return status; }
    public Instant getReadAt() { return readAt; }

    // Setters for fields that can change after creation (e.g., by services)
    public void setOriginalMessageId(String originalMessageId) { this.originalMessageId = originalMessageId; }
    public void setStatus(MessageStatus status) { this.status = status; }
    public void setReadAt(Instant readAt) { this.readAt = readAt; }

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
                (readAt != null ? ", readAt=" + readAt : "") +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Message message = (Message) o;
        return Objects.equals(messageId, message.messageId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(messageId);
    }
}
