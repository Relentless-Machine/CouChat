package com.couchat.conversation.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.conversation.model.Conversation;
import com.couchat.conversation.service.ConversationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * REST controller for conversation-related operations.
 */
@RestController
@RequestMapping("/api/conversations")
public class ConversationController {

    private static final Logger logger = LoggerFactory.getLogger(ConversationController.class);
    private final ConversationService conversationService;
    private final PasskeyAuthService passkeyAuthService; // To get current user context

    @Autowired
    public ConversationController(ConversationService conversationService, PasskeyAuthService passkeyAuthService) {
        this.conversationService = conversationService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Retrieves all conversations for the currently authenticated user.
     *
     * @param limit  Max number of conversations.
     * @param offset Offset for pagination.
     * @return A list of conversations.
     */
    @GetMapping
    public ResponseEntity<List<Conversation>> getMyConversations(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset) {
        String userId = passkeyAuthService.getLocalUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("GET /api/conversations - getMyConversations called for user: {} with limit: {}, offset: {}", userId, limit, offset);
        List<Conversation> conversations = conversationService.getConversationsForUser(userId, limit, offset);
        return ResponseEntity.ok(conversations);
    }

    /**
     * Gets a specific conversation by its ID.
     *
     * @param conversationId The ID of the conversation.
     * @return The conversation.
     */
    @GetMapping("/{conversationId}")
    public ResponseEntity<Conversation> getConversationById(@PathVariable String conversationId) {
        String userId = passkeyAuthService.getLocalUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("GET /api/conversations/{} - getConversationById called by user: {}", conversationId, userId);
        // TODO: Add permission check: ensure current user is part of this conversation
        Optional<Conversation> conversation = conversationService.getConversationById(conversationId);
        return conversation.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Creates a new individual conversation (simplified).
     * In a real application, this might be implicit when sending the first message.
     * @param peerId The ID of the other user to start a conversation with.
     * @return The new or existing conversation.
     */
    @PostMapping("/individual/{peerId}")
    public ResponseEntity<Conversation> createIndividualConversation(@PathVariable String peerId) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("POST /api/conversations/individual/{} - createIndividualConversation called by user: {}", peerId, currentUserId);
        try {
            Conversation conversation = conversationService.getOrCreateIndividualConversation(currentUserId, peerId);
            return ResponseEntity.status(HttpStatus.CREATED).body(conversation);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Updates flags for a conversation (archived, muted, pinned).
     *
     * @param conversationId The ID of the conversation.
     * @param updateRequest DTO containing flags to update.
     * @return The updated conversation.
     */
    @PatchMapping("/{conversationId}")
    public ResponseEntity<Conversation> updateConversationFlags(
            @PathVariable String conversationId,
            @RequestBody ConversationUpdateRequest updateRequest) {
        String userId = passkeyAuthService.getLocalUserId();
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("PATCH /api/conversations/{} - updateConversationFlags called by user: {}", conversationId, userId);
        // TODO: Add permission check: ensure current user is part of this conversation
        Optional<Conversation> updatedConversation = conversationService.updateConversationFlags(
                conversationId,
                userId, // Added userId argument here
                updateRequest.getIsArchived(),
                updateRequest.getIsMuted(),
                updateRequest.getIsPinned()
        );
        return updatedConversation.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    // Inner class for the update request payload
    public static class ConversationUpdateRequest {
        private Boolean isArchived;
        private Boolean isMuted;
        private Boolean isPinned;

        // Getters and setters
        public Boolean getIsArchived() { return isArchived; }
        public void setIsArchived(Boolean isArchived) { this.isArchived = isArchived; }
        public Boolean getIsMuted() { return isMuted; }
        public void setIsMuted(Boolean isMuted) { this.isMuted = isMuted; }
        public Boolean getIsPinned() { return isPinned; }
        public void setIsPinned(Boolean isPinned) { this.isPinned = isPinned; }
    }

    // TODO: Add endpoint for deleting a conversation (DELETE /{conversationId})
}
