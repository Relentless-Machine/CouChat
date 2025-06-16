// filepath: F:/Git/CouChat/src/main/java/com/couchat/messaging/service/MessageService.java
package com.couchat.messaging.service;

import com.couchat.messaging.model.Message;
import com.couchat.messaging.model.FileInfo;
import com.couchat.messaging.model.FileChunk;
import com.couchat.repository.MessageRepository;
import com.couchat.repository.ConversationRepository;
import com.couchat.conversation.model.Conversation; // Ensure this is the correct import
import com.couchat.p2p.P2PConnectionManager; // Added import for P2PConnectionManager
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy; // Added import for @Lazy
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap; // Added for FILE_TRANSFER_ERROR payload
import java.util.List;
import java.util.Map;   // Added for FILE_TRANSFER_ERROR payload
import java.util.Optional;
import java.util.UUID;

@Service
public class MessageService {

    private static final Logger logger = LoggerFactory.getLogger(MessageService.class);
    private final MessageRepository messageRepository;
    private final ConversationRepository conversationRepository;
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper; // Added ObjectMapper
    private final P2PConnectionManager p2pConnectionManager; // Added P2PConnectionManager

    @Autowired
    public MessageService(MessageRepository messageRepository,
                          ConversationRepository conversationRepository,
                          @Lazy P2PConnectionManager p2pConnectionManager) { // Added @Lazy to P2PConnectionManager
        this.messageRepository = messageRepository;
        this.conversationRepository = conversationRepository;
        this.p2pConnectionManager = p2pConnectionManager; // Initialize P2PConnectionManager
        this.objectMapper = new com.fasterxml.jackson.databind.ObjectMapper(); // Initialize ObjectMapper
        this.objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule()); // Register JavaTimeModule if not already configured globally
    }

    @Transactional
    public Message sendMessage(Message message) {
        logger.info("MessageService.sendMessage called for messageId: {}", message.getMessageId());

        if (message.getConversationId() == null) {
            if (message.getSenderId() != null && message.getRecipientId() != null &&
                !message.getSenderId().equals(message.getRecipientId()) &&
                (message.getType() == Message.MessageType.TEXT ||
                 message.getType() == Message.MessageType.FILE_INFO ||
                 message.getType() == Message.MessageType.FILE_CHUNK)) {
                logger.error("Message {} of type {} is missing a conversationId, which should have been set during creation. Proceeding, but this may indicate an issue.",
                             message.getMessageId(), message.getType());
            }
        }

        Message savedMessage = messageRepository.save(message);

        if (savedMessage != null && savedMessage.getConversationId() != null) {
            if (message.getSenderId() != null && message.getRecipientId() != null &&
                !message.getSenderId().equals(message.getRecipientId()) &&
                 (message.getType() == Message.MessageType.TEXT ||
                  message.getType() == Message.MessageType.FILE_INFO ||
                  message.getType() == Message.MessageType.FILE_CHUNK)) {
                try {
                    findOrCreateP2PConversation(savedMessage.getSenderId(), savedMessage.getRecipientId());
                } catch (IllegalArgumentException e) {
                    logger.error("Failed to ensure P2P conversation exists for message {}: {}", savedMessage.getMessageId(), e.getMessage());
                }
            }

            conversationRepository.updateLastMessageDetails(
                savedMessage.getConversationId(),
                savedMessage.getMessageId(),
                savedMessage.getTimestamp()
            );
            if (savedMessage.getRecipientId() != null && !savedMessage.getSenderId().equals(savedMessage.getRecipientId())) {
                 conversationRepository.incrementUnreadCount(savedMessage.getConversationId(), savedMessage.getRecipientId());
            }
        } else if (savedMessage != null && savedMessage.getConversationId() == null) {
            logger.error("Saved message {} but conversationId is still null. Last message details and unread count might not be updated.", savedMessage.getMessageId());
        }

        // Attempt to send the message via P2P after saving it
        if (savedMessage != null && savedMessage.getRecipientId() != null &&
            (savedMessage.getType() == Message.MessageType.TEXT ||
             savedMessage.getType() == Message.MessageType.FILE_INFO ||
             savedMessage.getType() == Message.MessageType.FILE_CHUNK || // Add other types that need direct P2P sending
             savedMessage.getType() == Message.MessageType.READ_RECEIPT )) { // Read receipts also go P2P
            try {
                logger.info("Attempting to send message {} to recipient {} via P2P.", savedMessage.getMessageId(), savedMessage.getRecipientId());
                p2pConnectionManager.sendMessage(savedMessage.getRecipientId(), savedMessage);
                // Note: P2PConnectionManager.sendMessage itself should handle if the connection is not active.
                // It currently logs a warning. We might want to update the message status here if P2P send fails immediately.
            } catch (Exception e) {
                logger.error("Error attempting to send message {} to {} via P2P: {}", savedMessage.getMessageId(), savedMessage.getRecipientId(), e.getMessage(), e);
                // Optionally, update message status to FAILED if P2P send throws an unexpected exception
                // savedMessage.setStatus(Message.MessageStatus.FAILED);
                // messageRepository.save(savedMessage); // Persist status change
            }
        }

        return savedMessage;
    }

    /**
     * Finds an existing P2P conversation or creates a new one if it doesn't exist.
     * The conversation ID is deterministically generated from userId1 and userId2.
     * Uses the full Conversation constructor.
     *
     * @param userId1 ID of the first user.
     * @param userId2 ID of the second user.
     * @return The existing or newly created P2P conversation.
     * @throws IllegalArgumentException if user IDs are invalid.
     */
    private Conversation findOrCreateP2PConversation(String userId1, String userId2) {
        if (userId1 == null || userId2 == null || userId1.trim().isEmpty() || userId2.trim().isEmpty() || userId1.equals(userId2)) {
            throw new IllegalArgumentException("User IDs for P2P conversation cannot be null, empty, or the same.");
        }

        String determinedConvId = determineConversationId(userId1, userId2);

        Optional<Conversation> existingConvOpt = conversationRepository.findById(determinedConvId);
        if (existingConvOpt.isPresent()) {
            logger.debug("Found existing P2P conversation with ID: {}", determinedConvId);
            return existingConvOpt.get();
        } else {
            logger.info("Creating new P2P conversation with determined ID: {}, User1: {}, User2: {}", determinedConvId, userId1, userId2);
            Instant now = Instant.now();
            Conversation newConversation = new Conversation(
                    determinedConvId,
                    userId2,
                    Conversation.ConversationType.INDIVIDUAL,
                    null,
                    null,
                    0,
                    false,
                    false,
                    false,
                    now,
                    now
            );
            return conversationRepository.save(newConversation);
        }
    }

    private String determineConversationId(String userId1, String userId2) {
        if (userId1 == null || userId2 == null || userId1.trim().isEmpty() || userId2.trim().isEmpty()) {
            throw new IllegalArgumentException("User IDs cannot be null or empty for determining conversation ID.");
        }
        String[] ids = {userId1, userId2};
        Arrays.sort(ids);
        return "p2p_" + String.join("_", ids);
    }

    // --- create...Message methods ---

    public Message createTextMessage(String senderId, String recipientId, String textContent) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.TEXT,
                senderId,
                recipientId,
                textContent,
                Instant.now(),
                null, // originalMessageId
                Message.MessageStatus.SENT,
                null  // readAt
        );
    }

    public Message createReplyMessage(String senderId, String recipientId, String textContent, String originalMessageId) {
        String conversationId = determineConversationId(senderId, recipientId);
        // Optional: Fetch original message to get its conversationId if needed for strict consistency
        // Optional<Message> originalMsg = messageRepository.findById(originalMessageId);
        // String convIdForReply = originalMsg.map(Message::getConversationId).orElse(conversationId);

        return new Message(
                UUID.randomUUID().toString(),
                conversationId, // or convIdForReply
                Message.MessageType.TEXT,
                senderId,
                recipientId,
                textContent,
                Instant.now(),
                originalMessageId,
                Message.MessageStatus.SENT,
                null
        );
    }

    public Message createFileInfoMessage(String senderId, String recipientId, FileInfo fileInfo) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_INFO,
                senderId,
                recipientId,
                fileInfo, // Payload is FileInfo object
                Instant.now(),
                null,
                Message.MessageStatus.INFO, // Changed to INFO for file control messages
                null
        );
    }

    public Message createFileChunkMessage(String senderId, String recipientId, FileChunk fileChunk) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_CHUNK,
                senderId,
                recipientId,
                fileChunk, // Payload is FileChunk object
                Instant.now(),
                null,
                Message.MessageStatus.INFO, // Changed to INFO for file control messages
                null
        );
    }

    public Message createFileTransferControlMessage(String senderId, String recipientId, Message.MessageType controlType, String fileId, String message) {
        String conversationId = determineConversationId(senderId, recipientId);
        Map<String, String> payload = new HashMap<>();
        payload.put("fileId", fileId);
        if (message != null) {
            payload.put("message", message);
        }
        // Ensure controlType is one of the expected file transfer control types
        if (controlType != Message.MessageType.FILE_TRANSFER_ACCEPTED && // Corrected enum name
            controlType != Message.MessageType.FILE_TRANSFER_REJECTED && // Corrected enum name
            controlType != Message.MessageType.FILE_TRANSFER_COMPLETE &&
            controlType != Message.MessageType.FILE_TRANSFER_ERROR) {
            throw new IllegalArgumentException("Invalid message type for file transfer control: " + controlType);
        }

        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                controlType,
                senderId,
                recipientId,
                payload, // Payload is a Map for control messages
                Instant.now(),
                null,
                Message.MessageStatus.INFO,
                null
        );
    }


    public Message createFileTransferAcceptedMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_TRANSFER_ACCEPTED,
                senderId,
                recipientId,
                fileId,
                Instant.now(),
                null,
                Message.MessageStatus.INFO,
                null
        );
    }

    public Message createFileTransferRejectedMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_TRANSFER_REJECTED,
                senderId,
                recipientId,
                fileId,
                Instant.now(),
                null,
                Message.MessageStatus.INFO,
                null
        );
    }

    public Message createFileTransferCancelledMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_TRANSFER_CANCELLED,
                senderId,
                recipientId,
                fileId,
                Instant.now(),
                null,
                Message.MessageStatus.INFO,
                null
        );
    }

    public Message createFileTransferCompleteMessage(String senderId, String recipientId, String fileId) {
        String conversationId = determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_TRANSFER_COMPLETE,
                senderId,
                recipientId,
                fileId,
                Instant.now(),
                null,
                Message.MessageStatus.INFO,
                null
        );
    }

    public Message createReadReceiptMessage(String senderId, String recipientId, String originalMessageId, String conversationIdParam) {
        String finalConversationId = (conversationIdParam != null && !conversationIdParam.isEmpty()) ?
                                     conversationIdParam : determineConversationId(senderId, recipientId);
        return new Message(
                UUID.randomUUID().toString(),
                finalConversationId,
                Message.MessageType.READ_RECEIPT,
                senderId,
                recipientId,
                originalMessageId,
                Instant.now(),
                null,
                Message.MessageStatus.DELIVERED,
                null
        );
    }

    public Message createFileTransferErrorMessage(String senderId, String recipientId, String fileId, String errorCode, String errorMessageText) {
        String conversationId = determineConversationId(senderId, recipientId);
        Map<String, String> payload = new HashMap<>();
        payload.put("fileId", fileId);
        payload.put("errorCode", errorCode);
        payload.put("errorMessage", errorMessageText);

        return new Message(
                UUID.randomUUID().toString(),
                conversationId,
                Message.MessageType.FILE_TRANSFER_ERROR,
                senderId,
                recipientId,
                payload,
                Instant.now(),
                null,
                Message.MessageStatus.ERROR,
                null
        );
    }

    @Transactional
    public void receiveTextMessage(Message message) {
        if (message == null || message.getType() != Message.MessageType.TEXT) {
            logger.warn("Received null message or non-TEXT message in receiveTextMessage: {}", message);
            return;
        }
        logger.info("Processing received TEXT message ID: {}, From: {}, To: {}, OriginalMsgID: {}",
                message.getMessageId(), message.getSenderId(), message.getRecipientId(), message.getOriginalMessageId());

        Message savedMessage = messageRepository.save(message);
        if (savedMessage != null) {
            conversationRepository.updateLastMessageDetails(
                    savedMessage.getConversationId(),
                    savedMessage.getMessageId(),
                    savedMessage.getTimestamp()
            );
            if (savedMessage.getRecipientId() != null && !savedMessage.getSenderId().equals(savedMessage.getRecipientId())) {
                 conversationRepository.incrementUnreadCount(savedMessage.getConversationId(), savedMessage.getRecipientId());
            }
            logger.info("Saved received TEXT message ID: {}", savedMessage.getMessageId());
        } else {
            logger.error("Failed to save received TEXT message ID: {}", message.getMessageId());
        }
    }

    @Transactional
    public void processReadReceipt(Message readReceiptMessage) {
        if (readReceiptMessage == null || readReceiptMessage.getType() != Message.MessageType.READ_RECEIPT) {
            logger.warn("Received null message or non-READ_RECEIPT message in processReadReceipt: {}", readReceiptMessage);
            return;
        }
        String originalMessageId = (String) readReceiptMessage.getPayload();
        String readerId = readReceiptMessage.getSenderId();

        logger.info("Processing READ_RECEIPT for original message ID: {} from reader: {}. Receipt ID: {}",
                originalMessageId, readerId, readReceiptMessage.getMessageId());

        Optional<Message> originalMessageOpt = messageRepository.findById(originalMessageId);
        if (originalMessageOpt.isPresent()) {
            Message originalMessage = originalMessageOpt.get();
            if (originalMessage.getRecipientId().equals(readerId)) {
                if (originalMessage.getReadAt() == null) {
                    originalMessage.setReadAt(readReceiptMessage.getTimestamp());
                    originalMessage.setStatus(Message.MessageStatus.READ);
                    messageRepository.save(originalMessage);
                    logger.info("Marked original message ID: {} as READ by {}. At: {}", originalMessageId, readerId, originalMessage.getReadAt());

                    if (originalMessage.getConversationId() != null) {
                        conversationRepository.resetUnreadCount(originalMessage.getConversationId(), readerId);
                        logger.info("Reset unread count for conversation {} for user {}", originalMessage.getConversationId(), readerId);
                    }
                } else {
                    logger.info("Original message ID: {} was already marked as read at {}. Ignoring new receipt from {}. Receipt time: {}",
                            originalMessageId, originalMessage.getReadAt(), readerId, readReceiptMessage.getTimestamp());
                }
            } else {
                logger.warn("Read receipt for message ID: {} received from unexpected user: {}. Original recipient was: {}. Ignoring.",
                        originalMessageId, readerId, originalMessage.getRecipientId());
            }
        } else {
            logger.warn("Received READ_RECEIPT for non-existent original message ID: {}. Receipt ID: {}",
                    originalMessageId, readReceiptMessage.getMessageId());
        }
    }

    // Added missing methods:

    public Optional<Message> getMessageById(String messageId) {
        logger.debug("Fetching message by ID: {}", messageId);
        // TODO: Add permission check: ensure the requesting user has access to this messageId
        return messageRepository.findById(messageId);
    }

    public List<Message> getMessagesByConversation(String conversationId, int limit, int offset) {
        logger.debug("Fetching messages for conversation ID: {}, Limit: {}, Offset: {}", conversationId, limit, offset);
        // TODO: Add permission check: ensure the requesting user is part of this conversation.
        return messageRepository.findByConversationIdOrderByTimestampDesc(conversationId, limit, offset);
    }

    @Transactional
    public void markMessagesAsRead(String conversationId, String userId) {
        logger.info("Marking messages as read for conversation ID: {} by user ID: {}", conversationId, userId);

        int updatedCount = messageRepository.markMessagesAsRead(conversationId, userId, Instant.now());
        logger.info("Marked {} messages as read in conversation {} for user {}", updatedCount, conversationId, userId);

        if (updatedCount > 0) {
            conversationRepository.resetUnreadCount(conversationId, userId);
            logger.info("Reset unread count for conversation {} for user {}", conversationId, userId);
        }
    }

    public Message processIncomingMessage(String senderId, String jsonData) {
        logger.debug("Processing incoming raw JSON data from sender {}: {}", senderId, jsonData);
        try {
            Message incomingMessage = objectMapper.readValue(jsonData, Message.class);
            // incomingMessage.setSenderId(senderId); // Sender ID is part of the Message object constructor or set by P2PConnection

            // Validate conversationId based on sender and (expected) local recipient
            // This step is crucial if conversationId is not part of the transmitted JSON or needs verification.
            // String localUserId = passkeyAuthService.getLocalUserId(); // Assuming you have a way to get local user ID
            // String expectedConversationId = determineConversationId(senderId, localUserId);
            // if (!expectedConversationId.equals(incomingMessage.getConversationId())) {
            //     logger.warn("Mismatch in conversation ID. Expected: {}, Actual: {}. Overriding or logging.",
            //                 expectedConversationId, incomingMessage.getConversationId());
            //     // Decide on a strategy: override, reject, or log.
            //     // incomingMessage.setConversationId(expectedConversationId); // Example: Override
            // }

            // Persist the message first
            Message savedMessage = sendMessage(incomingMessage); // sendMessage will handle conversation creation/update
            logger.info("Incoming message from {} processed and saved with ID: {}", incomingMessage.getSenderId(), savedMessage.getMessageId());


            // Further processing based on message type (e.g., if it\'s a control message for FileTransferService)
            // This is where you might delegate to FileTransferService if it\'s a FILE_INFO, FILE_CHUNK, etc.
            // For example:
            // if (savedMessage.getType() == Message.MessageType.FILE_INFO) {
            //     fileTransferService.handleIncomingFileInfo(savedMessage);\n            // } else if (savedMessage.getType() == Message.MessageType.FILE_CHUNK) {
            //     fileTransferService.handleIncomingFileChunk(savedMessage);\n            // }

            return savedMessage;
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) { // Fully qualify JsonProcessingException
            logger.error("Error deserializing incoming JSON message from sender {}: {}. JSON: {}", senderId, e.getMessage(), jsonData, e);
            return null;
        } catch (Exception e) {
            logger.error("Unexpected error processing incoming message from sender {}: {}. JSON: {}", senderId, e.getMessage(), jsonData, e);
            return null;
        }
    }
}
