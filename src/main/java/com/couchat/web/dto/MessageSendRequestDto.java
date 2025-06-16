package com.couchat.web.dto;

import com.couchat.messaging.model.Message; // Assuming MessageType is in Message class

public class MessageSendRequestDto {
    private String conversationId;
    private Message.MessageType type;
    private String recipientId; // Can be peerId or groupId
    private Object payload;
    private String originalMessageId; // For replies

    // Jackson will use a default no-arg constructor or one with @JsonCreator if needed
    // For simplicity, we'll rely on Jackson's default behavior or add getters/setters

    public MessageSendRequestDto() {
    }

    // Getters and Setters (important for Jackson deserialization and for service access)
    public String getConversationId() {
        return conversationId;
    }

    public void setConversationId(String conversationId) {
        this.conversationId = conversationId;
    }

    public Message.MessageType getType() {
        return type;
    }

    public void setType(Message.MessageType type) {
        this.type = type;
    }

    public String getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(String recipientId) {
        this.recipientId = recipientId;
    }

    public Object getPayload() {
        return payload;
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }

    public String getOriginalMessageId() {
        return originalMessageId;
    }

    public void setOriginalMessageId(String originalMessageId) {
        this.originalMessageId = originalMessageId;
    }

    @Override
    public String toString() {
        return "MessageSendRequestDto{" +
                "conversationId='" + conversationId + "\''" +
                ", type=" + type +
                ", recipientId='" + recipientId + "\''" +
                ", payload=" + (payload instanceof String && ((String) payload).length() > 50 ? ((String)payload).substring(0,50) + "..." : payload) +
                (originalMessageId != null ? ", originalMessageId='" + originalMessageId + "\''" : "") +
                '}';
    }
}

