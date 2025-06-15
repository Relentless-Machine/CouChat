package com.couchat.messaging.service;

import com.couchat.messaging.model.Message;
import com.couchat.messaging.model.FileInfo;
import com.couchat.messaging.model.FileChunk;
import com.couchat.repository.MessageRepository;
import com.couchat.repository.ConversationRepository;
import com.couchat.conversation.model.Conversation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for message-related operations.
 */
@Service
public class MessageService {

    private static final Logger logger = LoggerFactory.getLogger(MessageService.class);
    private final MessageRepository messageRepository;
    private final ConversationRepository conversationRepository;

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
            logger.warn("Message {} has no conversationId. This should be set by the caller or derived correctly.", message.getMessageId());
            // Attempt to derive conversation ID if not set, especially for TEXT messages.
            // This is a fallback and ideally conversation ID is set by the caller.
            if (message.getType() == Message.MessageType.TEXT && message.getRecipientId() != null) {
                String derivedConversationId = determineConversationId(message.getSenderId(), message.getRecipientId());
                // Message.conversationId is final, so we can't set it directly.
                // This implies the message object might need to be reconstructed or the design re-evaluated
                // if conversationId is to be dynamically assigned here.
                // For now, we log this situation.
                logger.info("Derived conversationId for message {}: {}", message.getMessageId(), derivedConversationId);
                // If the message object were mutable for conversationId, it would be:
                // message = new Message(message.getMessageId(), derivedConversationId, message.getSenderId(), ..., message.getPayload());
                // This is a significant change to Message immutability.
                // For now, we proceed with the original message, assuming the caller handles conversationId.
            }
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
     * @param messageId The ID of the message to retrieve.
     * @return An {@link Optional} containing the message if found, or empty otherwise.
     */
    public Optional<Message> getMessageById(String messageId) {
        logger.debug("Fetching message by ID: {}", messageId);
        return messageRepository.findById(messageId);
    }

    /**
     * Retrieves messages for a given conversation, with pagination.
     *
     * @param conversationId The ID of the conversation.
     * @param limit The maximum number of messages to retrieve.
     * @param offset The offset from where to start retrieving messages.
     * @return A list of messages.
     */
    public List<Message> getMessagesByConversation(String conversationId, int limit, int offset) {
        logger.debug("Fetching messages for conversation ID: {}, Limit: {}, Offset: {}", conversationId, limit, offset);
        return messageRepository.findByConversationIdOrderByTimestampDesc(conversationId, limit, offset);
    }

    /**
     * Marks messages in a conversation as read by a specific user.
     *
     * @param conversationId The ID of the conversation.
     * @param userId The ID of the user who read the messages.
     */
    @Transactional
    public void markMessagesAsRead(String conversationId, String userId) {
        logger.info("Marking messages as read for conversation ID: {} by user ID: {}", conversationId, userId);
        int updatedCount = messageRepository.markMessagesAsRead(conversationId, userId, Instant.now());
        logger.info("Marked {} messages as read in conversation {}", updatedCount, conversationId);
        if (updatedCount > 0) {
            conversationRepository.resetUnreadCount(conversationId, userId); // Assuming userId helps identify whose unread count to reset
        }
    }

    /**
     * Deletes a message by its ID.
     * Placeholder for actual deletion logic (e.g., soft delete or based on policy).
     *
     * @param messageId The ID of the message to delete.
     */
    public void deleteMessage(String messageId) {
        logger.info("Deleting message with ID: {} (placeholder)", messageId);
        // Actual deletion logic might involve messageRepository.deleteById(messageId)
        // or a soft delete mechanism.
        messageRepository.deleteById(messageId); // Example of hard delete
    }

    // --- Moved methods from com.couchat.messaging.MessageService ---

    private String determineConversationId(String userId1, String userId2) {
        if (userId1 == null || userId2 == null) {
            logger.warn("Cannot determine conversation ID with null user IDs: {} and {}", userId1, userId2);
            // Fallback or throw exception, for now, return a generic or error ID
            return "error_invalid_user_ids_" + UUID.randomUUID().toString();
        }
        // Ensure consistent order for the conversation ID
        String[] ids = {userId1, userId2};
        Arrays.sort(ids);
        return String.join("_", ids);
    }

    public Message createTextMessage(String senderId, String recipientId, String textContent) {
        String conversationId = determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.TEXT,
                textContent,
                Instant.now(),
                null, // originalMessageId
                null, // readAt
                Message.MessageStatus.SENT // Initial status
        );
        logger.info("Created TEXT message: ID {}, From {}, To {}, ConvID {}", message.getMessageId(), senderId, recipientId, conversationId);
        return message;
    }

    public Message createReplyMessage(String senderId, String recipientId, String textContent, String originalMessageId) {
        String conversationId = determineConversationId(senderId, recipientId); // Or get from original message
        // Potentially, conversationId should be fetched from the originalMessage if it's a reply
        // This needs careful consideration based on how conversations are managed.
        // For now, assume it's a direct peer-to-peer conversation.
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.TEXT, // Replies are also TEXT messages but link to an original
                textContent,
                Instant.now(),
                originalMessageId,
                null, // readAt
                Message.MessageStatus.SENT // Initial status
        );
        logger.info("Created REPLY message: ID {}, From {}, To {}, OriginalMsgID {}, ConvID {}",
                    message.getMessageId(), senderId, recipientId, originalMessageId, conversationId);
        return message;
    }

    public Message createFileInfoMessage(String senderId, String recipientId, FileInfo fileInfo) {
        String conversationId = determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_INFO,
                fileInfo, // Payload is the FileInfo object
                Instant.now(),
                null,
                null,
                Message.MessageStatus.SENT
        );
        logger.info("Created FILE_INFO message: ID {}, FileID {}, FileName {}, From {}, To {}, ConvID {}",
                    message.getMessageId(), fileInfo.getFileId(), fileInfo.getFileName(), senderId, recipientId, conversationId);
        return message;
    }

    public Message createFileChunkMessage(String senderId, String recipientId, FileChunk fileChunk) {
        String conversationId = determineConversationId(senderId, recipientId); // Or get from an active file transfer session
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_CHUNK,
                fileChunk, // Payload is the FileChunk object
                Instant.now(),
                null,
                null,
                Message.MessageStatus.SENT // Or a more specific status like PENDING_UPLOAD if chunks are queued
        );
        // Avoid logging chunk data directly
        logger.info("Created FILE_CHUNK message: ID {}, FileID {}, ChunkIdx {}, From {}, To {}, ConvID {}",
                    message.getMessageId(), fileChunk.getFileId(), fileChunk.getChunkIndex(), senderId, recipientId, conversationId);
        return message;
    }

    public Message createFileTransferAcceptedMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_TRANSFER_ACCEPTED,
                fileId, // Payload is the fileId string
                Instant.now(),
                null,
                null,
                Message.MessageStatus.INFO // This is a control message
        );
        logger.info("Created FILE_TRANSFER_ACCEPTED message: ID {}, FileID {}, From {}, To {}, ConvID {}",
                    message.getMessageId(), fileId, senderId, recipientId, conversationId);
        return message;
    }

    public Message createFileTransferRejectedMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_TRANSFER_REJECTED,
                fileId, // Payload is the fileId string
                Instant.now(),
                null,
                null,
                Message.MessageStatus.INFO
        );
        logger.info("Created FILE_TRANSFER_REJECTED message: ID {}, FileID {}, From {}, To {}, ConvID {}",
                    message.getMessageId(), fileId, senderId, recipientId, conversationId);
        return message;
    }

    public Message createFileTransferCancelledMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_TRANSFER_CANCELLED,
                fileId, // Payload is the fileId string
                Instant.now(),
                null,
                null,
                Message.MessageStatus.INFO
        );
        logger.info("Created FILE_TRANSFER_CANCELLED message: ID {}, FileID {}, From {}, To {}, ConvID {}",
                    message.getMessageId(), fileId, senderId, recipientId, conversationId);
        return message;
    }

    public Message createFileTransferCompleteMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_TRANSFER_COMPLETE,
                fileId, // Payload is the fileId string
                Instant.now(),
                null,
                null,
                Message.MessageStatus.INFO
        );
        logger.info("Created FILE_TRANSFER_COMPLETE message: ID {}, FileID {}, From {}, To {}, ConvID {}",
                    message.getMessageId(), fileId, senderId, recipientId, conversationId);
        return message;
    }

    public Message createReadReceiptMessage(String senderId, String recipientId, String originalMessageId, String conversationId) {
        // For read receipts, conversationId should ideally come from the context of the message being acknowledged.
        // Using determineConversationId might not be correct if the provided conversationId is for a group.
        // However, if conversationId is provided, use it. Otherwise, determine for P2P.
        String finalConversationId = (conversationId != null && !conversationId.isEmpty()) ?
                                     conversationId : determineConversationId(senderId, recipientId);
        Message message = new Message(
                UUID.randomUUID().toString(),
                finalConversationId,
                senderId, // The user who read the message
                recipientId, // The original sender of the message being acknowledged
                Message.MessageType.READ_RECEIPT,
                originalMessageId, // Payload is the ID of the message that was read
                Instant.now(),
                null, // No original message for a receipt itself in terms of reply
                null, // readAt is not applicable for the receipt itself
                Message.MessageStatus.DELIVERED_TO_SERVER // Or a more specific status for receipts
        );
        logger.info("Created READ_RECEIPT message: ID {}, OriginalMsgID {}, Reader {}, OriginalSender {}, ConvID {}",
                    message.getMessageId(), originalMessageId, senderId, recipientId, finalConversationId);
        return message;
    }

    /**
     * Processes a received text message (normal or reply) and saves it.
     *
     * @param message The received text message.
     */
    @Transactional
    public void receiveTextMessage(Message message) {
        if (message == null || message.getType() != Message.MessageType.TEXT) {
            logger.warn("Received null message or non-TEXT message in receiveTextMessage: {}", message);
            return;
        }
        logger.info("Processing received TEXT message ID: {}, From: {}, To: {}, OriginalMsgID: {}",
                message.getMessageId(), message.getSenderId(), message.getRecipientId(), message.getOriginalMessageId());

        // Ensure conversationId is present, if not, try to determine it (especially for P2P)
        // This part might need more robust logic if conversationId is missing
        String conversationId = message.getConversationId();
        if (conversationId == null && message.getRecipientId() != null) {
            conversationId = determineConversationId(message.getSenderId(), message.getRecipientId());
            // As Message is immutable for conversationId, this implies the received message object
            // should have had it, or P2PConnection/caller should set it before calling this.
            // For now, we log and proceed if it was determinable for P2P.
            logger.warn("Received TEXT message {} without conversationId. Determined: {}. Consider setting it earlier.",
                        message.getMessageId(), conversationId);
            // To properly save with this conversationId, the message object would need to be reconstructed.
            // This is a design consideration. For now, we save the message as is, or if we decide
            // to enforce conversationId, we might throw an error or not save.
            // Let's assume for now the message object is reconstructed by the caller if convId was missing and now determined.
            // Or, the Message object needs a setter or a constructor that allows setting it post-determination.
            // Given Message is immutable, the caller (P2PConnection) should create it with the correct conversationId.
        }
        if (message.getConversationId() == null && conversationId != null) {
             logger.warn("Message {} still has null conversationId after determination. This indicates an issue in message construction.", message.getMessageId());
             // Fallback: use the determined one for repository operations if absolutely necessary and if Message model were mutable
             // For now, we rely on the message object passed in.
        }


        Message savedMessage = messageRepository.save(message);
        if (savedMessage != null) {
            conversationRepository.updateLastMessageDetails(
                    savedMessage.getConversationId(),
                    savedMessage.getMessageId(),
                    savedMessage.getTimestamp()
            );
            // TODO: Increment unread count for recipient (message.getRecipientId()) in the conversation
            // TODO: Notify frontend/UI about the new message
            logger.info("Saved received TEXT message ID: {}", savedMessage.getMessageId());
        } else {
            logger.error("Failed to save received TEXT message ID: {}", message.getMessageId());
        }
    }

    /**
     * Processes a received read receipt and updates the status of the original message.
     *
     * @param readReceiptMessage The read receipt message.
     */
    @Transactional
    public void processReadReceipt(Message readReceiptMessage) {
        if (readReceiptMessage == null || readReceiptMessage.getType() != Message.MessageType.READ_RECEIPT) {
            logger.warn("Received null message or non-READ_RECEIPT message in processReadReceipt: {}", readReceiptMessage);
            return;
        }
        String originalMessageId = (String) readReceiptMessage.getPayload();
        String readerId = readReceiptMessage.getSenderId(); // The user who sent the receipt (i.e., read the message)

        logger.info("Processing READ_RECEIPT for original message ID: {} from reader: {}. Receipt ID: {}",
                originalMessageId, readerId, readReceiptMessage.getMessageId());

        Optional<Message> originalMessageOpt = messageRepository.findById(originalMessageId);
        if (originalMessageOpt.isPresent()) {
            Message originalMessage = originalMessageOpt.get();
            // Ensure the receipt is from the intended recipient of the original message
            if (originalMessage.getRecipientId().equals(readerId)) {
                if (originalMessage.getReadAt() == null) { // Only update if not already marked as read
                    originalMessage.setReadAt(readReceiptMessage.getTimestamp()); // Assuming Message has setReadAt
                    originalMessage.setStatus(Message.MessageStatus.READ);      // Assuming Message has setStatus
                    messageRepository.save(originalMessage);
                    logger.info("Marked original message ID: {} as READ by {}.", originalMessageId, readerId);
                    // TODO: Notify frontend/UI about the updated message status

                    // Update conversation's unread count if applicable
                    // This logic might be more complex depending on how unread counts are managed per user
                    if (originalMessage.getConversationId() != null) {
                         // The user who sent the original message is originalMessage.getSenderId()
                         // The user who read it is readerId (originalMessage.getRecipientId())
                         // We need to reset unread count for originalMessage.getSenderId() regarding messages from readerId in this conversation.
                         // This is a bit simplified; typically, unread count is for the *recipient* of the *original* message.
                         // When a message is read, the *sender* of that original message sees the status update.
                         // The unread count for the *reader* (readerId) for *this specific message* becomes 0.
                         // The conversation unread count for 'readerId' should be decremented.
                        conversationRepository.decrementUnreadCount(originalMessage.getConversationId(), readerId);
                        logger.info("Decremented unread count for conversation {} for user {}", originalMessage.getConversationId(), readerId);
                    }

                } else {
                    logger.info("Original message ID: {} was already marked as read at {}. Ignoring new receipt from {}.",
                            originalMessageId, originalMessage.getReadAt(), readerId);
                }
            } else {
                logger.warn("Read receipt for message ID: {} received from unexpected user: {}. Original recipient was: {}. Ignoring.",
                        originalMessageId, readerId, originalMessage.getRecipientId());
            }
        } else {
            logger.warn("Received READ_RECEIPT for non-existent original message ID: {}. Receipt ID: {}",
                    originalMessageId, readReceiptMessage.getMessageId());
        }
        // Save the receipt message itself if needed (e.g., for auditing or history)
        // messageRepository.save(readReceiptMessage); // This might be redundant if receipts aren't stored like regular messages
    }

    public Message createFileTransferErrorMessage(String senderId, String recipientId, String fileId, String errorCode, String errorMessageText) {
        String conversationId = determineConversationId(senderId, recipientId);
        Map<String, String> payload = new java.util.HashMap<>();
        payload.put("fileId", fileId);
        payload.put("errorCode", errorCode);
        payload.put("errorMessage", errorMessageText);

        Message message = new Message(
                UUID.randomUUID().toString(),
                conversationId,
                senderId,
                recipientId,
                Message.MessageType.FILE_TRANSFER_ERROR,
                payload, // Payload is the map
                Instant.now(),
                null,
                null,
                Message.MessageStatus.ERROR
        );
        logger.info("Created FILE_TRANSFER_ERROR message: ID {}, FileID {}, From {}, To {}, Error: {}, Details: {}",
                message.getMessageId(), fileId, senderId, recipientId, errorCode, errorMessageText);
        return message;
    }
}
