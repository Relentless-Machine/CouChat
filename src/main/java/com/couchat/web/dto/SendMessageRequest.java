package com.couchat.web.dto;

/**
 * Data Transfer Object for a send message request.
 */
public class SendMessageRequest {
    private String recipientId;
    private String content;

    // Getters and Setters
    public String getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(String recipientId) {
        this.recipientId = recipientId;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @Override
    public String toString() {
        return "SendMessageRequest{" +
               "recipientId='" + recipientId + '\'' +
               ", content='" + (content != null && content.length() > 30 ? content.substring(0, 30) + "..." : content) + '\'' +
               '}';
    }
}
