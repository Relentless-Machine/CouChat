package com.couchat.web.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.messaging.MessageService;
import com.couchat.messaging.model.Message;
import com.couchat.p2p.P2PConnectionManager;
import com.couchat.web.dto.SendMessageRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST Controller for handling message-related operations.
 */
@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private static final Logger logger = LoggerFactory.getLogger(MessageController.class);

    private final MessageService messageService;
    private final P2PConnectionManager p2pConnectionManager;
    private final PasskeyAuthService passkeyAuthService;

    /**
     * Constructs a MessageController.
     *
     * @param messageService       Service for creating and processing messages.
     * @param p2pConnectionManager Manager for P2P connections.
     * @param passkeyAuthService   Service for retrieving local user authentication details.
     */
    @Autowired
    public MessageController(MessageService messageService,
                             P2PConnectionManager p2pConnectionManager,
                             PasskeyAuthService passkeyAuthService) {
        this.messageService = messageService;
        this.p2pConnectionManager = p2pConnectionManager;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Endpoint to send a text message to a peer.
     *
     * @param request The {@link SendMessageRequest} containing the recipient ID and message content.
     * @return ResponseEntity indicating success or failure.
     */
    @PostMapping("/send")
    public ResponseEntity<String> sendTextMessage(@RequestBody SendMessageRequest request) {
        if (!passkeyAuthService.isAuthenticated()) {
            logger.warn("Send message request failed: User not authenticated.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        String localUserId = passkeyAuthService.getLocalUserId();
        if (localUserId == null || localUserId.isEmpty()) {
            logger.error("Send message request failed: Local user ID is not available.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Local user ID not available.");
        }

        if (request == null || request.getRecipientId() == null || request.getRecipientId().isEmpty() ||
            request.getContent() == null || request.getContent().isEmpty()) {
            logger.warn("Send message request failed: Invalid request data. {}", request);
            return ResponseEntity.badRequest().body("Recipient ID and content must be provided.");
        }

        logger.info("Received request to send message from {} to {}: {}", localUserId, request.getRecipientId(), request.getContent());

        try {
            Message textMessage = messageService.createTextMessage(
                    localUserId,
                    request.getRecipientId(),
                    request.getContent()
            );

            p2pConnectionManager.sendMessage(request.getRecipientId(), textMessage);
            logger.info("Message queued for sending from {} to {}. Message ID: {}", localUserId, request.getRecipientId(), textMessage.getMessageId());
            return ResponseEntity.ok("Message sent successfully. ID: " + textMessage.getMessageId());
        } catch (Exception e) {
            logger.error("Failed to send message from {} to {}. Content: {}. Error: {}",
                         localUserId, request.getRecipientId(), request.getContent(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to send message: " + e.getMessage());
        }
    }
}
