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
     * Updates conversation properties like archived, muted, pinned status.
     *
     * @param conversationId The ID of the conversation.
     * @param isArchived New archived status (optional).
     * @param isMuted New muted status (optional).
     * @param isPinned New pinned status (optional).
     * @return The updated conversation or empty if not found.
     */
    @Transactional
    public Optional<Conversation> updateConversationFlags(String conversationId, Boolean isArchived, Boolean isMuted, Boolean isPinned) {
        logger.info("ConversationService.updateConversationFlags for id: {}", conversationId);
        Optional<Conversation> convOpt = conversationRepository.findById(conversationId);
        if (convOpt.isEmpty()) {
            return Optional.empty();
        }
        Conversation conversation = convOpt.get();
        boolean updated = false;
        if (isArchived != null && conversation.isArchived() != isArchived) {
            conversationRepository.updateArchivedStatus(conversationId, isArchived);
            conversation.setArchived(isArchived);
            updated = true;
        }
        if (isMuted != null && conversation.isMuted() != isMuted) {
            conversationRepository.updateMutedStatus(conversationId, isMuted);
            conversation.setMuted(isMuted);
            updated = true;
        }
        if (isPinned != null && conversation.isPinned() != isPinned) {
            conversationRepository.updatePinnedStatus(conversationId, isPinned);
            conversation.setPinned(isPinned);
            updated = true;
        }
        if (updated) {
            conversation.setUpdatedAt(Instant.now()); // Manually update timestamp if flags changed
            // conversationRepository.save(conversation); // Or rely on individual update methods to touch updated_at
        }
        return Optional.of(conversation);
    }

    /**
     * Deletes a conversation.
     * @param conversationId The ID of the conversation to delete.
     * @return true if successful.
     */
    @Transactional
    public boolean deleteConversation(String conversationId) {
        logger.info("ConversationService.deleteConversation called for id: {}", conversationId);
        // Business logic before deleting (e.g., notify users, archive instead of delete)
        // The ON DELETE CASCADE on messages.conversation_id will handle message deletion.
        return conversationRepository.deleteById(conversationId);
    }
}

