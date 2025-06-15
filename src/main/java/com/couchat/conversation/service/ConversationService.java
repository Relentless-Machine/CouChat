package com.couchat.conversation.service;

import com.couchat.conversation.model.Conversation;
import com.couchat.repository.ConversationRepository;
import com.couchat.repository.UserRepository; // For fetching user details for conversation names etc.
import com.couchat.repository.GroupRepository;  // For fetching group details
import com.couchat.user.model.User;
import com.couchat.group.model.Group;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for conversation-related operations.
 */
@Service
public class ConversationService {

    private static final Logger logger = LoggerFactory.getLogger(ConversationService.class);
    private final ConversationRepository conversationRepository;
    private final UserRepository userRepository; // Optional: for enriching conversation data
    private final GroupRepository groupRepository;   // Optional: for enriching group conversation data

    @Autowired
    public ConversationService(ConversationRepository conversationRepository,
                               UserRepository userRepository,
                               GroupRepository groupRepository) {
        this.conversationRepository = conversationRepository;
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
    }

    /**
     * Creates a new conversation or retrieves an existing one, especially for individual chats.
     *
     * @param userId1 The ID of the first user.
     * @param userId2 The ID of the second user.
     * @return The existing or newly created conversation.
     */
    @Transactional
    public Conversation getOrCreateIndividualConversation(String userId1, String userId2) {
        if (userId1.equals(userId2)) {
            throw new IllegalArgumentException("Cannot create a conversation with oneself.");
        }
        // Normalize peer order to ensure a unique conversation for a pair of users
        String peer1 = userId1.compareTo(userId2) < 0 ? userId1 : userId2;
        String peer2 = userId1.compareTo(userId2) < 0 ? userId2 : userId1;
        String syntheticTargetPeerId = peer1 + "_" + peer2; // Example of a consistent target ID for 1-1

        // Attempt to find existing conversation by a synthetic ID or by checking both users
        // This logic depends on how targetPeerId is structured for individual chats.
        // For now, let's assume targetPeerId for an individual chat is the *other* user's ID.
        // This means two conversation entries might exist for one chat (one for each user's perspective)
        // or a single entry with a combined/normalized target_peer_id.
        // The current schema uses a single target_peer_id.

        // Simplified: find by (user1, user2) or (user2, user1) if target_peer_id is the other user.
        // This part needs a clear strategy for how individual conversations are identified.
        // Let's assume for now the service ensures a single conversation object per pair.
        // The `findByTargetPeerIdAndType` is more for finding a conversation from one user's perspective.

        // For a robust solution, a composite key or a normalized peer ID in the conversations table
        // for INDIVIDUAL chats would be better. The current schema has `target_peer_id`.
        // If `target_peer_id` is always the *other* user, then we need to check both ways or have a convention.

        // Let's assume a convention: target_peer_id is the ID of the user who is NOT the initiator
        // or a lexicographically sorted concatenation for a unique ID.
        // For this stub, we'll simplify: if a conversation with either as target exists, we use it.
        // This is not fully robust for ensuring a single conversation entity for a pair.

        // Try finding based on (user1 as initiator, user2 as target) or (user2 as initiator, user1 as target)
        // This logic is complex because `conversations.target_peer_id` is just one ID.
        // A better approach for 1-1 chats is often to have a conversation ID derived from both user IDs.

        // For this stub, we'll just create a new one if not obviously found.
        // This part of the logic is highly dependent on the exact schema and query strategy for 1-to-1.
        // The `findAllByUserId` in ConversationRepository is more about listing, not finding a specific 1-to-1.

        // Let's use a simplified approach for the stub: create a new conversation for one perspective.
        // The caller would typically know who the "other" peer is.
        // This method is more about ensuring a conversation object exists for a pair.

        // This stub will just log and return a new or dummy conversation for now.
        logger.info("getOrCreateIndividualConversation called for users: {} and {}. STUBBED.", userId1, userId2);
        // In a real implementation, you would query for an existing conversation
        // e.g., WHERE (userA = userId1 AND userB = userId2) OR (userA = userId2 AND userB = userId1)
        // For now, we assume one of them is the targetPeerId for the conversation entry.
        Optional<Conversation> convOpt = conversationRepository.findByTargetPeerIdAndType(userId2, Conversation.ConversationType.INDIVIDUAL);
        if (convOpt.isPresent()) { // Simplistic check
            // Further check if this conversation actually involves userId1
            // This requires more info or a different query in repository
            return convOpt.get();
        }
        Conversation newConversation = new Conversation(userId2, Conversation.ConversationType.INDIVIDUAL);
        return conversationRepository.save(newConversation);
    }

    /**
     * Retrieves a conversation by its ID.
     *
     * @param conversationId The ID of the conversation.
     * @return An Optional containing the conversation if found.
     */
    public Optional<Conversation> getConversationById(String conversationId) {
        logger.info("ConversationService.getConversationById called for id: {}", conversationId);
        return conversationRepository.findById(conversationId);
    }

    /**
     * Retrieves all conversations for a given user (paginated).
     *
     * @param userId The user's ID.
     * @param limit  Page size.
     * @param offset Page offset.
     * @return A list of conversations.
     */
    public List<Conversation> getConversationsForUser(String userId, int limit, int offset) {
        logger.info("ConversationService.getConversationsForUser called for userId: {}", userId);
        return conversationRepository.findAllByUserId(userId, limit, offset);
        // TODO: Enrich conversations with user/group names if needed for display
    }

    /**
     * Updates the flags (archived, muted, pinned) for a conversation for a specific user.
     *
     * @param conversationId The ID of the conversation.
     * @param userId The ID of the user for whom these flags are being set.
     * @param isArchived     New archived status.
     * @param isMuted        New muted status.
     * @param isPinned       New pinned status.
     * @return Optional containing the updated conversation, or empty if not found.
     */
    @Transactional
    public Optional<Conversation> updateConversationFlags(String conversationId, String userId, Boolean isArchived, Boolean isMuted, Boolean isPinned) {
        logger.info("ConversationService.updateConversationFlags for id: {}, userId: {}", conversationId, userId);
        Optional<Conversation> convOpt = conversationRepository.findById(conversationId);
        if (convOpt.isEmpty()) {
            logger.warn("Conversation not found with id: {}", conversationId);
            return Optional.empty();
        }
        Conversation conversation = convOpt.get();
        boolean updated = false;
        if (isArchived != null && conversation.isArchived() != isArchived) {
            // Pass userId and unbox Boolean to boolean
            conversationRepository.updateArchivedStatus(conversationId, userId, isArchived);
            conversation.setArchived(isArchived);
            updated = true;
        }
        if (isMuted != null && conversation.isMuted() != isMuted) {
            // Pass userId and unbox Boolean to boolean
            conversationRepository.updateMutedStatus(conversationId, userId, isMuted);
            conversation.setMuted(isMuted);
            updated = true;
        }
        if (isPinned != null && conversation.isPinned() != isPinned) {
            // Pass userId and unbox Boolean to boolean
            conversationRepository.updatePinnedStatus(conversationId, userId, isPinned);
            conversation.setPinned(isPinned);
            updated = true;
        }
        if (updated) {
            // Consider if the repository 'update' methods should also update the 'updated_at' timestamp.
            // If not, setting it here is appropriate.
            conversation.setUpdatedAt(Instant.now());
            // We've updated parts of the conversation state.
            // The individual repository update methods handle DB persistence for flags.
            // If other parts of 'conversation' object itself need saving, uncomment next line.
            // conversationRepository.save(conversation);
        }
        return Optional.of(conversation);
    }

    /**
     * Deletes a conversation.
     * Note: The underlying repository method `deleteById` returns void.
     * This service method returns true if the operation is attempted without exceptions,
     * not necessarily confirming a row was deleted.
     * @param conversationId The ID of the conversation to delete.
     * @return true if the delete operation was called without error.
     */
    @Transactional
    public boolean deleteConversation(String conversationId) {
        logger.info("ConversationService.deleteConversation called for id: {}", conversationId);
        // Business logic before deleting (e.g., notify users, archive instead of delete)
        try {
            conversationRepository.deleteById(conversationId);
            // If deleteById throws an exception (e.g., DataAccessException), it won't reach here.
            return true;
        } catch (Exception e) {
            logger.error("Error deleting conversation with id: {}", conversationId, e);
            return false;
        }
    }
}
