// filepath: F:/Git/CouChat/src/main/java/com/couchat/repository/MessageRepository.java
package com.couchat.repository;

import com.couchat.messaging.model.Message;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface MessageRepository {

    /**
     * Saves a new message or updates an existing one.
     *
     * @param message The message to save.
     * @return The saved message, potentially with updated fields (e.g., generated ID or timestamp if not set).
     */
    Message save(Message message);

    /**
     * Finds a message by its unique ID.
     *
     * @param messageId The ID of the message.
     * @return An {@link Optional} containing the message if found, or empty otherwise.
     */
    Optional<Message> findById(String messageId);

    /**
     * Finds all messages belonging to a specific conversation, ordered by timestamp descending.
     * Supports pagination.
     *
     * @param conversationId The ID of the conversation.
     * @param limit The maximum number of messages to return.
     * @param offset The number of messages to skip (for pagination).
     * @return A list of messages.
     */
    List<Message> findByConversationIdOrderByTimestampDesc(String conversationId, int limit, int offset);

    /**
     * Marks messages in a given conversation as read by a specific user up to a certain time.
     * This method should update the readAt timestamp and status of relevant messages.
     *
     * @param conversationId The ID of the conversation.
     * @param userId The ID of the user who is reading the messages (typically the recipient of these messages).
     * @param readAtTimestamp The timestamp indicating when the messages were read. All messages in the
     *                        conversation for this user before or at this timestamp should be marked as read.
     * @return The number of messages updated.
     */
    int markMessagesAsRead(String conversationId, String userId, Instant readAtTimestamp);

    /**
     * Deletes a message by its ID.
     *
     * @param messageId The ID of the message to delete.
     */
    void deleteById(String messageId);

    // Add other methods as needed, e.g.:
    // List<Message> findUnreadMessages(String conversationId, String userId);
    // long countUnreadMessages(String conversationId, String userId);
    // int updateMessageStatus(String messageId, Message.MessageStatus newStatus);
}

