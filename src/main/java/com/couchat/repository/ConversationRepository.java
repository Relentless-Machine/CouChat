// filepath: F:/Git/CouChat/src/main/java/com/couchat/repository/ConversationRepository.java
package com.couchat.repository;

import com.couchat.conversation.model.Conversation;
import com.couchat.conversation.model.Conversation.ConversationType; // Assuming ConversationType is an inner enum
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface ConversationRepository {

    Conversation save(Conversation conversation);

    Optional<Conversation> findById(String conversationId);

    /**
     * Finds all conversations for a given user, with pagination.
     */
    List<Conversation> findAllByUserId(String userId, int limit, int offset);

    Optional<Conversation> findByTargetPeerIdAndType(String targetPeerOrGroupId, ConversationType type);

    /**
     * Updates the last message details for a conversation.
     * Ensures return type is void.
     */
    void updateLastMessageDetails(String conversationId, String lastMessageId, Instant lastMessageTimestamp);

    int resetUnreadCount(String conversationId, String userId);

    int decrementUnreadCount(String conversationId, String userId);

    int incrementUnreadCount(String conversationId, String userId);

    // Methods required by ConversationService
    int updateArchivedStatus(String conversationId, String userId, boolean isArchived);

    int updateMutedStatus(String conversationId, String userId, boolean isMuted);

    int updatePinnedStatus(String conversationId, String userId, boolean isPinned);

    // Changed to match common repository patterns, assuming userId might not always be part of conversationId for deletion query
    void deleteById(String conversationId);

}

