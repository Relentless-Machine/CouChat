package com.couchat.repository;

import com.couchat.messaging.model.Message;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for {@link Message} entities.
 * Handles database operations such as storing, retrieving, and updating messages.
 */
public interface MessageRepository {

    /**
     * Saves a new message to the database or updates an existing one.
     *
     * @param message The {@link Message} object to save.
     * @return The saved {@link Message} object, potentially with updated fields (e.g., generated ID or timestamp if not set).
     *         Returns null or throws an exception if saving fails.
     */
    Message save(Message message);

    /**
     * Finds a message by its unique ID.
     *
     * @param messageId The ID of the message to find.
     * @return An {@link Optional} containing the {@link Message} if found, or an empty Optional otherwise.
     */
    Optional<Message> findById(String messageId);

    /**
     * Updates the status of a specific message.
     *
     * @param messageId The ID of the message to update.
     * @param newStatus The new {@link Message.MessageStatus}.
     * @return true if the status was updated successfully, false otherwise.
     */
    boolean updateMessageStatus(String messageId, Message.MessageStatus newStatus);

    /**
     * Retrieves all messages belonging to a specific conversation, ordered by timestamp.
     *
     * @param conversationId The ID of the conversation.
     * @param limit The maximum number of messages to retrieve.
     * @param offset The starting point for retrieving messages (for pagination).
     * @return A list of {@link Message} objects, ordered by timestamp (typically descending for recent messages first).
     */
    List<Message> findByConversationIdOrderByTimestampDesc(String conversationId, int limit, int offset);

    /**
     * Retrieves messages in a conversation that are newer than a given timestamp.
     *
     * @param conversationId The ID of the conversation.
     * @param afterTimestamp The timestamp after which messages should be retrieved.
     * @return A list of {@link Message} objects.
     */
    List<Message> findByConversationIdAndTimestampAfter(String conversationId, Instant afterTimestamp);

    /**
     * Retrieves all reply messages for a given original message ID, ordered by timestamp.
     *
     * @param originalMessageId The ID of the message for which replies are sought.
     * @return A list of {@link Message} objects that are replies, ordered by timestamp.
     */
    List<Message> findRepliesByOriginalMessageIdOrderByTimestampAsc(String originalMessageId);

    /**
     * Retrieves all messages with a specific status (e.g., PENDING) for a user.
     * This can be used to find messages that failed to send or are awaiting delivery confirmation.
     *
     * @param userId The ID of the user (can be sender or recipient depending on context and status).
     * @param status The {@link Message.MessageStatus} to filter by.
     * @return A list of {@link Message} objects matching the criteria.
     */
    List<Message> findMessagesByUserIdAndStatus(String userId, Message.MessageStatus status);

    /**
     * Deletes a message by its ID.
     * Note: Depending on application policy, this might be a soft delete.
     *
     * @param messageId The ID of the message to delete.
     * @return true if the message was deleted successfully, false otherwise.
     */
    boolean deleteById(String messageId);

    /**
     * Counts the number of unread messages in a specific conversation for a specific user.
     *
     * @param conversationId The ID of the conversation.
     * @param userId The ID of the user for whom to count unread messages (typically the recipient).
     * @return The number of unread messages.
     */
    long countUnreadMessagesByConversationIdAndUserId(String conversationId, String userId);

    /**
     * Marks all messages in a conversation as read for a specific user (recipient).
     *
     * @param conversationId The ID of the conversation.
     * @param userId The ID of the user (recipient) whose messages are to be marked as read.
     * @return The number of messages updated to READ status.
     */
    int markMessagesAsRead(String conversationId, String userId);

}
