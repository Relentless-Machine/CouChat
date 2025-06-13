package com.couchat.messaging.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.messaging.model.Message;
import com.couchat.messaging.service.MessageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST controller for message-related operations.
 */
@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private static final Logger logger = LoggerFactory.getLogger(MessageController.class);
    private final MessageService messageService;
    private final PasskeyAuthService passkeyAuthService; // To get current user as sender

    @Autowired
    public MessageController(MessageService messageService, PasskeyAuthService passkeyAuthService) {
        this.messageService = messageService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Sends a new message.
     * The client is expected to set the conversationId, type, recipientId (if applicable), and payload.
     * SenderId will be derived from the authenticated user.
     */
    @PostMapping
    public ResponseEntity<Message> sendMessage(@RequestBody Message message) {
        String senderId = passkeyAuthService.getLocalUserId();
        if (senderId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Create a new message instance to ensure senderId is correctly set and not client-tampered,
        // and to allow Message constructor to generate messageId and initial timestamp.
        // The client-sent 'message' object is treated as a DTO here.
        Message newMessage = new Message(
            message.getConversationId(),
            message.getType(),
            senderId,
            message.getRecipientId(), // RecipientId from client is used here
            message.getPayload()
        );
        if (message.getOriginalMessageId() != null) {
            newMessage.setOriginalMessageId(message.getOriginalMessageId());
        }
        // Status will be PENDING by default from constructor

        logger.info("POST /api/messages - sendMessage called by sender: {} for conversation: {}", senderId, newMessage.getConversationId());

        try {
            Message savedMessage = messageService.sendMessage(newMessage);
            return ResponseEntity.status(HttpStatus.CREATED).body(savedMessage);
        } catch (IllegalArgumentException e) {
            logger.error("Error sending message: {}", e.getMessage());
            return ResponseEntity.badRequest().body(null); // Or a DTO with error info
        } catch (Exception e) {
            logger.error("Unexpected error sending message", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Retrieves messages for a specific conversation with pagination.
     *
     * @param conversationId The ID of the conversation.
     * @param limit Max number of messages (optional, default can be set).
     * @param offset Offset for pagination (optional, default can be set).
     * @return A list of messages.
     */
    @GetMapping("/conversation/{conversationId}")
    public ResponseEntity<List<Message>> getMessagesByConversation(
            @PathVariable String conversationId,
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset) {
        logger.info("GET /api/messages/conversation/{} - getMessagesByConversation called with limit: {}, offset: {}",
                    conversationId, limit, offset);
        // TODO: Add permission check: ensure current user is part of this conversation
        List<Message> messages = messageService.getMessagesByConversation(conversationId, limit, offset);
        return ResponseEntity.ok(messages);
    }

    /**
     * Marks messages in a conversation as read by the current user.
     *
     * @param conversationId The ID of the conversation.
     * @return ResponseEntity indicating success or failure.
     */
    @PostMapping("/conversation/{conversationId}/read")
    public ResponseEntity<Void> markConversationAsRead(@PathVariable String conversationId) {
        String userId = passkeyAuthService.getLocalUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("POST /api/messages/conversation/{}/read - markConversationAsRead called by user: {}", conversationId, userId);
        try {
            messageService.markMessagesAsRead(conversationId, userId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            logger.error("Error marking conversation {} as read for user {}: {}", conversationId, userId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Gets a specific message by its ID.
     * @param messageId The ID of the message.
     * @return The message.
     */
    @GetMapping("/{messageId}")
    public ResponseEntity<Message> getMessageById(@PathVariable String messageId) {
        logger.info("GET /api/messages/{} - getMessageById called", messageId);
        // TODO: Add permission check: ensure current user has access to this message
        Optional<Message> message = messageService.getMessageById(messageId);
        return message.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    // TODO: Add endpoint for deleting a message (DELETE /{messageId})
}

