package com.couchat.repository;

import com.couchat.conversation.model.Conversation;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for {@link Conversation} entities.
 * Defines a contract for data access operations related to conversations.
 */
public interface ConversationRepository {

    /**
     * Saves a new conversation or updates an existing one in the database.
     *
     * @param conversation The {@link Conversation} object to save. Must not be null.
     * @return The saved {@link Conversation} object.
     */
    Conversation save(Conversation conversation);

    /**
     * Finds a conversation by its unique ID.
     *
     * @param conversationId The ID of the conversation to find. Must not be null.
     * @return An {@link Optional} containing the {@link Conversation} if found, or an empty Optional otherwise.
     */
    Optional<Conversation> findById(String conversationId);

    /**
     * Finds a conversation by its target peer ID and type.
     * This is useful for retrieving a specific individual or group chat.
     *
     * @param targetPeerId The ID of the target peer (user or group). Must not be null.
     * @param type The type of conversation (INDIVIDUAL or GROUP). Must not be null.
     * @return An {@link Optional} containing the {@link Conversation} if found, or an empty Optional otherwise.
     */
    Optional<Conversation> findByTargetPeerIdAndType(String targetPeerId, Conversation.ConversationType type);

    /**
     * Retrieves all conversations a specific user is involved in.
     * For individual chats, this means conversations where the user is the targetPeerId (or implicitly the other party).
     * For group chats, this means conversations where the user is a member of the group identified by targetPeerId.
     * Results are typically ordered by the last message timestamp to show recent conversations first.
     *
     * @param userId The ID of the user whose conversations are to be retrieved. Must not be null.
     * @param limit The maximum number of conversations to retrieve.
     * @param offset The starting point for retrieving conversations (for pagination).
     * @return A list of {@link Conversation} objects, ordered by `updated_at` or `last_message_timestamp` descending.
     */
    List<Conversation> findAllByUserId(String userId, int limit, int offset);

    /**
     * Deletes a conversation by its unique ID.
     * Note: This might not delete the messages themselves, depending on application policy.
     * Associated messages might be orphaned or handled by a cleanup process if not deleted via cascade.
     *
     * @param conversationId The ID of the conversation to delete. Must not be null.
     * @return true if the conversation was deleted successfully, false otherwise.
     */
    boolean deleteById(String conversationId);

    /**
     * Updates the last message ID and timestamp for a conversation.
     * This is typically called when a new message is sent or received in the conversation.
     *
     * @param conversationId The ID of the conversation to update. Must not be null.
     * @param lastMessageId The ID of the new last message. Can be null.
     * @param lastMessageTimestamp The timestamp of the new last message. Can be null.
     * @return true if the update was successful, false otherwise.
     */
    boolean updateLastMessageDetails(String conversationId, String lastMessageId, java.time.Instant lastMessageTimestamp);

    /**
     * Updates the unread message count for a conversation.
     *
     * @param conversationId The ID of the conversation. Must not be null.
     * @param unreadCount The new unread message count.
     * @return true if the update was successful, false otherwise.
     */
    boolean updateUnreadCount(String conversationId, int unreadCount);

    /**
     * Updates the archived status of a conversation.
     *
     * @param conversationId The ID of the conversation. Must not be null.
     * @param isArchived The new archived status.
     * @return true if the update was successful, false otherwise.
     */
    boolean updateArchivedStatus(String conversationId, boolean isArchived);

    /**
     * Updates the muted status of a conversation.
     *
     * @param conversationId The ID of the conversation. Must not be null.
     * @param isMuted The new muted status.
     * @return true if the update was successful, false otherwise.
     */
    boolean updateMutedStatus(String conversationId, boolean isMuted);

    /**
     * Updates the pinned status of a conversation.
     *
     * @param conversationId The ID of the conversation. Must not be null.
     * @param isPinned The new pinned status.
     * @return true if the update was successful, false otherwise.
     */
    boolean updatePinnedStatus(String conversationId, boolean isPinned);
}

