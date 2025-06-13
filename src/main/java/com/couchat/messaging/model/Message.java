package com.couchat.messaging.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

/**
 * Represents a generic message exchanged between peers.
 */
public class Message implements Serializable {
    private static final long serialVersionUID = 1L; // For Serializable interface

    private final String messageId;
    private final MessageType type;
    private final String senderId;
    private final String recipientId; // Can be a peerId or groupId
    private final Instant timestamp;
    private final Object payload; // Actual content (e.g., text, file metadata)

    // Optional fields, can be added based on specific needs
    private String originalMessageId; // For replies
    private MessageStatus status;     // E.g., SENT, DELIVERED, READ (client-side concern mostly)

    public enum MessageType {
        TEXT,
        FILE_INFO, // Information about a file to be transferred
        FILE_CHUNK, // A chunk of a file
        FILE_TRANSFER_ACCEPTED, // Recipient accepts the file transfer
        FILE_TRANSFER_REJECTED, // Recipient rejects the file transfer
        FILE_TRANSFER_COMPLETE, // Sent by sender or receiver to confirm completion
        FILE_TRANSFER_ERROR,    // Indicates an error during file transfer
        FILE_TRANSFER_CANCELLED,// User cancelled the file transfer
        READ_RECEIPT,
        TYPING_INDICATOR,
        // System messages
        SYSTEM_ERROR,
        SYSTEM_INFO
        // Add other types as needed (e.g., for group operations, status updates)
    }

    public enum MessageStatus { // Primarily for UI/client-side logic
        PENDING,   // Locally stored, not yet sent
        SENT,      // Sent to the network/peer
        DELIVERED, // Confirmed delivery to the peer's device
        READ,      // Confirmed read by the peer
        FAILED     // Sending failed
    }

    public Message(MessageType type, String senderId, String recipientId, Object payload) {
        this.messageId = UUID.randomUUID().toString();
        this.type = type;
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.payload = payload;
        this.timestamp = Instant.now();
    }

    // Getters
    public String getMessageId() {
        return messageId;
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

    public void setOriginalMessageId(String originalMessageId) {
        this.originalMessageId = originalMessageId;
    }

    public MessageStatus getStatus() {
        return status;
    }

    public void setStatus(MessageStatus status) {
        this.status = status;
    }

    @Override
    public String toString() {
        return "Message{" +
                "messageId='" + messageId + '\'' +
                ", type=" + type +
                ", senderId='" + senderId + '\'' +
                ", recipientId='" + recipientId + '\'' +
                ", timestamp=" + timestamp +
                ", payload=" + (payload instanceof String && ((String) payload).length() > 50 ? ((String)payload).substring(0,50) + "..." : payload) +
                (originalMessageId != null ? ", originalMessageId='" + originalMessageId + '\'' : "") +
                (status != null ? ", status=" + status : "") +
                '}';
    }
}
