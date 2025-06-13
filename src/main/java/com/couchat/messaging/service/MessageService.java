package com.couchat.messaging.service;

import com.couchat.messaging.model.Message;
import com.couchat.repository.MessageRepository;
import com.couchat.repository.ConversationRepository;
import com.couchat.conversation.model.Conversation;
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
 * Service layer for message-related operations.
 * Provides stub or minimal implementations for now.
 */
@Service
public class MessageService {

    private static final Logger logger = LoggerFactory.getLogger(MessageService.class);
    private final MessageRepository messageRepository;
    private final ConversationRepository conversationRepository; // Added ConversationRepository

    // TODO: Inject other necessary services like NotificationService, FileTransferService, EncryptionService

    @Autowired
    public MessageService(MessageRepository messageRepository, ConversationRepository conversationRepository) {
        this.messageRepository = messageRepository;
        this.conversationRepository = conversationRepository;
    }

    /**
     * Sends a new message.
     * This involves saving the message and updating conversation metadata.
     *
     * @param message The message to send.
     * @return The saved message.
     */
    @Transactional
    public Message sendMessage(Message message) {
        logger.info("MessageService.sendMessage called for messageId: {}", message.getMessageId());
        // Ensure conversation exists or create it (simplified here)
        // The conversationId should be set on the message object before calling this method.
        if (message.getConversationId() == null) {
            // This logic might be more complex: find existing or create new conversation
            // For now, assuming conversationId is pre-set or derived correctly by the caller.
            logger.warn("Message {} has no conversationId. This should be set by the caller.", message.getMessageId());
            // throw new IllegalArgumentException("Conversation ID must be set on the message.");
            // For demo purposes, let's try to find or create one if not set.
            // This is a simplified approach and might need refinement.
            String conversationId = findOrCreateConversationForMessage(message);
            // message.setConversationId(conversationId); // Message.conversationId is final
            // This implies message needs to be reconstructed or conversationId passed differently.
            // For now, this highlights a design consideration.
        }

        Message savedMessage = messageRepository.save(message);
        if (savedMessage != null) {
            conversationRepository.updateLastMessageDetails(
                savedMessage.getConversationId(),
                savedMessage.getMessageId(),
                savedMessage.getTimestamp()
            );
            // TODO: Increment unread count for recipient(s) in the conversation
            // TODO: Send push notification to recipient(s)
        }
        return savedMessage;
    }

    private String findOrCreateConversationForMessage(Message message) {
        // Simplified: Assumes individual chat for now if conversationId is missing.
        // This is not robust and needs proper handling in a real application.
        // For group messages, conversationId (groupId) must be known.
        if (message.getRecipientId() == null || message.getSenderId().equals(message.getRecipientId())) {
            logger.error("Cannot determine or create conversation for message without valid recipientId: {}", message);
            throw new IllegalArgumentException("Invalid recipient for conversation creation.");
        }

        // Try to find existing individual conversation (either way)
        Optional<Conversation> existingConvOpt = conversationRepository.findByTargetPeerIdAndType(message.getRecipientId(), Conversation.ConversationType.INDIVIDUAL);
        if (existingConvOpt.isPresent() && existingConvOpt.get().getTargetPeerId().equals(message.getSenderId())) { // Check if sender matches target of found conv
             return existingConvOpt.get().getConversationId();
        }
        existingConvOpt = conversationRepository.findByTargetPeerIdAndType(message.getSenderId(), Conversation.ConversationType.INDIVIDUAL);
        if (existingConvOpt.isPresent() && existingConvOpt.get().getTargetPeerId().equals(message.getRecipientId())) { // Check if recipient matches target of found conv
            return existingConvOpt.get().getConversationId();
        }

        // Create new individual conversation
        // For individual chats, targetPeerId in Conversation can be the *other* user.
        // Let's assume the service creating the message sets the conversationId correctly.
        // This fallback is a bit messy and indicates a need for clearer conversation management upstream.
        logger.warn("Attempting to create a new conversation implicitly for message {}. This path should be reviewed.", message.getMessageId());
        Conversation newConversation = new Conversation(message.getRecipientId(), Conversation.ConversationType.INDIVIDUAL);
        // The conversation should also know about the other participant (message.getSenderId()).
        // The current Conversation model might need adjustment or this logic needs to be in a ConversationService.
        conversationRepository.save(newConversation);
        return newConversation.getConversationId();
    }


    /**
     * Retrieves a message by its ID.
     *
     * @param messageId The ID of the message.
     * @return An Optional containing the message if found.
     */
    public Optional<Message> getMessageById(String messageId) {
        logger.info("MessageService.getMessageById called for messageId: {}", messageId);
        return messageRepository.findById(messageId);
    }

    /**
     * Retrieves messages for a specific conversation with pagination.
     *
     * @param conversationId The conversation ID.
     * @param limit Max number of messages.
     * @param offset Offset for pagination.
     * @return A list of messages.
     */
    public List<Message> getMessagesByConversation(String conversationId, int limit, int offset) {
        logger.info("MessageService.getMessagesByConversation called for conversationId: {}", conversationId);
        return messageRepository.findByConversationIdOrderByTimestampDesc(conversationId, limit, offset);
    }

    /**
     * Marks messages in a conversation as read by a user.
     *
     * @param conversationId The conversation ID.
     * @param userId The user ID for whom messages are marked read.
     */
    @Transactional
    public void markMessagesAsRead(String conversationId, String userId) {
        logger.info("MessageService.markMessagesAsRead called for conversationId: {}, userId: {}", conversationId, userId);
        messageRepository.markMessagesAsRead(conversationId, userId);
        conversationRepository.updateUnreadCount(conversationId, 0); // Reset unread count for this user
        // Note: unread count logic might be more complex if it's per user per conversation.
        // The current conversation.unread_count is a single field.
        // This implies the unread_count on the conversation might be for the *other* user in a 1-1 chat,
        // or a general indicator for groups. This needs clarification based on requirements.
    }

    /**
     * Deletes a message by its ID.
     * (Service might add more logic here, e.g., checking permissions)
     *
     * @param messageId The ID of the message to delete.
     * @return true if deletion was successful.
     */
    public boolean deleteMessage(String messageId) {
        logger.info("MessageService.deleteMessage called for messageId: {}", messageId);
        // TODO: Add permission checks if necessary
        // TODO: Handle file deletions if it's a file message
        return messageRepository.deleteById(messageId);
    }
}

