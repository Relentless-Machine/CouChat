package com.couchat.messaging;

import com.couchat.messaging.model.FileChunk;
import com.couchat.messaging.model.FileInfo;
import com.couchat.messaging.model.Message;
import com.couchat.transfer.FileTransferService; // Import FileTransferService
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.util.Map; // Added import for Map

/**
 * Service responsible for processing incoming messages and preparing outgoing messages.
 * Handles serialization and deserialization of {@link Message} objects to/from JSON.
 */
@Service
public class MessageService {

    private static final Logger logger = LoggerFactory.getLogger(MessageService.class);
    private final ObjectMapper objectMapper;
    private FileTransferService fileTransferService; // Lazy loaded to avoid circular dependency

    public MessageService() {
        this.objectMapper = new ObjectMapper();
        // Register JSR310 module to correctly serialize/deserialize Java Time types like Instant
        this.objectMapper.registerModule(new JavaTimeModule());
        logger.info("MessageService initialized with Jackson ObjectMapper.");
    }

    // Setter for FileTransferService to break circular dependency
    // Spring will call this after both beans are created.
    @org.springframework.beans.factory.annotation.Autowired
    public void setFileTransferService(FileTransferService fileTransferService) {
        this.fileTransferService = fileTransferService;
    }

    /**
     * Processes an incoming decrypted message string from a peer.
     * The string is expected to be a JSON representation of a {@link Message} object.
     *
     * @param peerId The ID of the peer from whom the message was received.
     * @param decryptedJsonMessage The decrypted JSON message content.
     */
    public void processIncomingMessage(String peerId, String decryptedJsonMessage) {
        try {
            Message message = objectMapper.readValue(decryptedJsonMessage, Message.class);
            logger.info("Received message from peer {}: Type: {}, ID: {}, Timestamp: {}",
                        peerId, message.getType(), message.getMessageId(), message.getTimestamp());

            switch (message.getType()) {
                case TEXT:
                    if (message.getPayload() instanceof String) {
                        String textContent = (String) message.getPayload();
                        if (message.getOriginalMessageId() != null && !message.getOriginalMessageId().isEmpty()) {
                            logger.info("TEXT message (reply) from {}: '{}' replying to messageId: {}",
                                        peerId, textContent, message.getOriginalMessageId());
                            // TODO: [Database] Store reply message, linking to originalMessageId.
                            // TODO: [UI] Notify frontend about the new reply message.
                        } else {
                            logger.info("TEXT message from {}: {}", peerId, textContent);
                            // TODO: [Database] Store text message (ID: {}, Peer: {}) in local database.
                            // TODO: [UI] Notify frontend about the new text message from peer {}.
                        }
                    } else {
                        logger.warn("Received TEXT message from {} with unexpected payload type: {}. Expected String, got {}.",
                                    peerId, message.getPayload(),
                                    message.getPayload() != null ? message.getPayload().getClass().getName() : "null");
                    }
                    break;
                case FILE_INFO:
                    try {
                        FileInfo fileInfo = objectMapper.convertValue(message.getPayload(), FileInfo.class);
                        logger.info("FILE_INFO received from {}: {}", peerId, fileInfo);
                        if (fileTransferService != null) {
                            // Ensure senderId from the message object is used
                            fileTransferService.handleIncomingFileInfo(fileInfo, message.getSenderId());
                        } else {
                            logger.error("FileTransferService not available to handle FILE_INFO from peer {}. Message ID: {}", peerId, message.getMessageId());
                        }
                    } catch (IllegalArgumentException e) {
                        logger.error("Failed to convert payload to FileInfo for message {} from peer {}. Payload: {}. Error: {}",
                                     message.getMessageId(), peerId, message.getPayload(), e.getMessage(), e);
                    }
                    break;
                case FILE_CHUNK:
                    try {
                        FileChunk fileChunk = objectMapper.convertValue(message.getPayload(), FileChunk.class);
                        logger.info("FILE_CHUNK received from {}: File ID: {}, Chunk Index: {}, Size: {} bytes",
                                    peerId, fileChunk.getFileId(), fileChunk.getChunkIndex(),
                                    fileChunk.getData() != null ? fileChunk.getData().length : 0);
                        if (fileTransferService != null) {
                             // Ensure senderId from the message object is used
                            fileTransferService.handleIncomingFileChunk(fileChunk, message.getSenderId());
                        } else {
                            logger.error("FileTransferService not available to handle FILE_CHUNK from peer {}. Message ID: {}", peerId, message.getMessageId());
                        }
                    } catch (IllegalArgumentException e) {
                        logger.error("Failed to convert payload to FileChunk for message {} from peer {}. Payload: {}. Error: {}",
                                     message.getMessageId(), peerId, message.getPayload(), e.getMessage(), e);
                    }
                    break;
                // Removed duplicate FILE_TRANSFER_ACCEPTED case here, it's handled below.
                case FILE_TRANSFER_REJECTED: // Assuming you will add this handler in FileTransferService
                case FILE_TRANSFER_CANCELLED: // Assuming you will add this handler in FileTransferService
                    if (message.getPayload() instanceof String) {
                        String fileIdForControl = (String) message.getPayload();
                        logger.info("Received {} for file ID: {} from peer: {}", message.getType(), fileIdForControl, message.getSenderId());
                        if (fileTransferService != null) {
                            switch (message.getType()) {
                                case FILE_TRANSFER_REJECTED:
                                    // fileTransferService.handleFileTransferRejected(fileIdForControl, message.getSenderId());
                                    logger.warn("FILE_TRANSFER_REJECTED handling not fully implemented yet in FileTransferService for fileId {}", fileIdForControl);
                                    // For now, treat as a generic error or log
                                    fileTransferService.handleFileTransferErrorMessage(fileIdForControl, message.getSenderId(), "REJECTED", "Transfer rejected by peer");
                                    break;
                                case FILE_TRANSFER_CANCELLED:
                                    // fileTransferService.handleFileTransferCancelled(fileIdForControl, message.getSenderId());
                                    logger.warn("FILE_TRANSFER_CANCELLED handling not fully implemented yet in FileTransferService for fileId {}", fileIdForControl);
                                    // For now, treat as a generic error or log
                                    fileTransferService.handleFileTransferErrorMessage(fileIdForControl, message.getSenderId(), "CANCELLED", "Transfer cancelled by peer");
                                    break;
                            }
                        } else {
                            logger.error("FileTransferService not available to handle {} from peer {}. File ID: {}",
                                         message.getType(), message.getSenderId(), fileIdForControl);
                        }
                    } else {
                        logger.warn("Received {} from {} with unexpected payload type: {}. Expected String (fileId), got {}. Message ID: {}",
                                    message.getType(), message.getSenderId(), message.getPayload(),
                                    message.getPayload() != null ? message.getPayload().getClass().getName() : "null", message.getMessageId());
                    }
                    break;
                case FILE_TRANSFER_ACCEPTED: // This is the primary handler for FILE_TRANSFER_ACCEPTED
                    if (message.getPayload() instanceof String) {
                        String acceptedFileId = (String) message.getPayload();
                        logger.info("Received FILE_TRANSFER_ACCEPTED for file ID: {} from peer: {}", acceptedFileId, message.getSenderId());
                        if (fileTransferService != null) {
                            fileTransferService.handleFileTransferAccepted(acceptedFileId, message.getSenderId());
                        } else {
                             logger.error("FileTransferService not available to handle FILE_TRANSFER_ACCEPTED from peer {}. File ID: {}", message.getSenderId(), acceptedFileId);
                        }
                    } else {
                         logger.warn("Received FILE_TRANSFER_ACCEPTED from {} with unexpected payload type: {}. Expected String (fileId), got {}. Message ID: {}",
                                    message.getSenderId(), message.getPayload(),
                                    message.getPayload() != null ? message.getPayload().getClass().getName() : "null", message.getMessageId());
                    }
                    break;
                case FILE_TRANSFER_COMPLETE:
                    if (message.getPayload() instanceof String) {
                        String completedFileId = (String) message.getPayload();
                        logger.info("Received FILE_TRANSFER_COMPLETE for file ID: {} from peer: {}", completedFileId, message.getSenderId());
                        if (fileTransferService != null) {
                            fileTransferService.handleFileTransferCompleteMessage(completedFileId, message.getSenderId());
                        } else {
                            logger.error("FileTransferService not available to handle FILE_TRANSFER_COMPLETE from peer {}. File ID: {}", message.getSenderId(), completedFileId);
                        }
                    } else {
                        logger.warn("Received FILE_TRANSFER_COMPLETE from {} with unexpected payload type: {}. Expected String (fileId), got {}. Message ID: {}",
                                    message.getSenderId(), message.getPayload(),
                                    message.getPayload() != null ? message.getPayload().getClass().getName() : "null", message.getMessageId());
                    }
                    break;
                case FILE_TRANSFER_ERROR:
                    // Payload for FILE_TRANSFER_ERROR should ideally be a structured object
                    // For now, assuming it might be a simple string (fileId) or a more complex object
                    // Let's assume FileTransferService's handleFileTransferErrorMessage can parse it or expect specific parts
                    if (message.getPayload() instanceof String) { // Simple case: payload is just the fileId
                        String errorFileId = (String) message.getPayload();
                        logger.info("Received FILE_TRANSFER_ERROR for file ID: {} from peer: {}", errorFileId, message.getSenderId());
                        if (fileTransferService != null) {
                            // Default error message if not more specific info in payload
                            fileTransferService.handleFileTransferErrorMessage(errorFileId, message.getSenderId(), "PEER_REPORTED", "Error reported by peer");
                        } else {
                            logger.error("FileTransferService not available to handle FILE_TRANSFER_ERROR from peer {}. File ID: {}", message.getSenderId(), errorFileId);
                        }
                    } else if (message.getPayload() instanceof Map) { // More complex case: payload is a map
                        try {
                            Map<String, String> errorPayload = objectMapper.convertValue(message.getPayload(), Map.class);
                            String errorFileId = errorPayload.get("fileId");
                            String errorCode = errorPayload.getOrDefault("errorCode", "UNKNOWN");
                            String errorMessageText = errorPayload.getOrDefault("errorMessage", "Error reported by peer");
                            if (errorFileId != null) {
                                logger.info("Received FILE_TRANSFER_ERROR for file ID: {} from peer: {}. Code: {}, Message: {}", errorFileId, message.getSenderId(), errorCode, errorMessageText);
                                if (fileTransferService != null) {
                                    fileTransferService.handleFileTransferErrorMessage(errorFileId, message.getSenderId(), errorCode, errorMessageText);
                                } else {
                                    logger.error("FileTransferService not available to handle FILE_TRANSFER_ERROR from peer {}. File ID: {}", message.getSenderId(), errorFileId);
                                }
                            } else {
                                logger.warn("Received FILE_TRANSFER_ERROR from {} with Map payload missing 'fileId'. Payload: {}. Message ID: {}",
                                            message.getSenderId(), message.getPayload(), message.getMessageId());
                            }
                        } catch (IllegalArgumentException e) {
                            logger.error("Failed to convert FILE_TRANSFER_ERROR payload Map for message {} from peer {}. Payload: {}. Error: {}",
                                         message.getMessageId(), message.getSenderId(), message.getPayload(), e.getMessage(), e);
                        }
                    } else {
                        logger.warn("Received FILE_TRANSFER_ERROR from {} with unexpected payload type: {}. Message ID: {}",
                                    message.getSenderId(),
                                    message.getPayload() != null ? message.getPayload().getClass().getName() : "null", message.getMessageId());
                    }
                    break;
                case READ_RECEIPT:
                    // Assuming payload for READ_RECEIPT is the messageId of the message that was read.
                    if (message.getPayload() instanceof String) {
                        String readMessageId = (String) message.getPayload();
                        logger.info("READ_RECEIPT received from {} for messageId: {}", peerId, readMessageId);
                        // TODO: [Database] Update status of message (ID: {}) to 'READ' in local database.
                        // This would involve calling a method like:
                        // messageRepository.updateMessageStatus(readMessageId, Message.MessageStatus.READ);
                        // TODO: [UI] Notify UI to update the displayed status of message (ID: {}).
                        // Example: eventPublisher.publishEvent(new MessageReadEvent(this, peerId, readMessageId));
                        // For now, just logging.
                        System.out.println("Received read receipt for message: " + readMessageId + " from peer: " + peerId);
                    } else {
                        logger.warn("Received READ_RECEIPT from {} with unexpected payload type: {}", peerId, message.getPayload().getClass().getName());
                    }
                    break;
                // Add cases for other message types like TYPING_INDICATOR, FILE_TRANSFER_COMPLETE etc.
                default:
                    logger.warn("Received message of unhandled type {} from peer {}. Message details: {}",
                                message.getType(), peerId, message);
                    break;
            }

        } catch (JsonProcessingException e) {
            logger.error("Failed to deserialize incoming message from peer {}. JSON: {}. Error: {}",
                         peerId,
                         decryptedJsonMessage.length() > 200 ? decryptedJsonMessage.substring(0,200) + "..." : decryptedJsonMessage,
                         e.getMessage(), e);
            // TODO: Handle deserialization error (e.g., notify sender, log to error queue)
        }
    }

    /**
     * Prepares an outgoing {@link Message} object to be sent to a peer.
     * Serializes the Message object to a JSON string.
     *
     * @param message The {@link Message} object to send.
     * @return A JSON string representation of the message, or null if serialization fails.
     */
    public String prepareOutgoingMessage(Message message) {
        if (message == null) {
            logger.warn("Attempted to prepare a null outgoing message.");
            return null;
        }
        try {
            String jsonMessage = objectMapper.writeValueAsString(message);
            logger.info("Prepared outgoing message for peer {}: {}", message.getRecipientId(), message);
            return jsonMessage;
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize outgoing message: {}. Error: {}", message, e.getMessage(), e);
            return null;
        }
    }

    // Example of creating a specific type of message (can be in a factory or helper class too)
    /**
     * Creates a new text message.
     *
     * @param senderId The ID of the sender.
     * @param recipientId The ID of the recipient.
     * @param textContent The text content of the message.
     * @return A {@link Message} object of type TEXT.
     */
    public Message createTextMessage(String senderId, String recipientId, String textContent) {
        return new Message(Message.MessageType.TEXT, senderId, recipientId, textContent);
    }

    /**
     * Creates a new text message that is a reply to an existing message.
     *
     * @param senderId The ID of the sender.
     * @param recipientId The ID of the recipient.
     * @param textContent The text content of the reply message.
     * @param originalMessageId The ID of the message being replied to.
     * @return A {@link Message} object of type TEXT, with originalMessageId set.
     */
    public Message createReplyTextMessage(String senderId, String recipientId, String textContent, String originalMessageId) {
        Message replyMessage = new Message(Message.MessageType.TEXT, senderId, recipientId, textContent);
        replyMessage.setOriginalMessageId(originalMessageId);
        // Optionally set status to PENDING or SENT immediately
        // replyMessage.setStatus(Message.MessageStatus.PENDING);
        return replyMessage;
    }

    /**
     * Creates a new file information message.
     * Used to initiate a file transfer by sending metadata about the file.
     *
     * @param senderId    The ID of the sender.
     * @param recipientId The ID of the recipient.
     * @param fileInfo    The {@link FileInfo} object containing file metadata.
     * @return A {@link Message} object of type FILE_INFO.
     */
    public Message createFileInfoMessage(String senderId, String recipientId, FileInfo fileInfo) {
        return new Message(Message.MessageType.FILE_INFO, senderId, recipientId, fileInfo);
    }

    /**
     * Creates a new file chunk message.
     * Used to send a chunk of a file during a file transfer.
     *
     * @param senderId    The ID of the sender.
     * @param recipientId The ID of the recipient.
     * @param fileChunk   The {@link FileChunk} object containing the file data chunk.
     * @return A {@link Message} object of type FILE_CHUNK.
     */
    public Message createFileChunkMessage(String senderId, String recipientId, FileChunk fileChunk) {
        return new Message(Message.MessageType.FILE_CHUNK, senderId, recipientId, fileChunk);
    }

    /**
     * Creates a new file transfer accepted message.
     *
     * @param senderId     The ID of the local user (who is accepting).
     * @param recipientId  The ID of the original sender of the file.
     * @param fileId       The ID of the file transfer being accepted.
     * @return A {@link Message} object of type FILE_TRANSFER_ACCEPTED.
     */
    public Message createFileTransferAcceptedMessage(String senderId, String recipientId, String fileId) {
        return new Message(Message.MessageType.FILE_TRANSFER_ACCEPTED, senderId, recipientId, fileId);
    }

    /**
     * Creates a new file transfer complete message.
     * Sent by the sender when all chunks have been successfully sent.
     *
     * @param senderId     The ID of the local user (who completed sending).
     * @param recipientId  The ID of the recipient of the file.
     * @param fileId       The ID of the completed file transfer.
     * @return A {@link Message} object of type FILE_TRANSFER_COMPLETE.
     */
    public Message createFileTransferCompleteMessage(String senderId, String recipientId, String fileId) {
        return new Message(Message.MessageType.FILE_TRANSFER_COMPLETE, senderId, recipientId, fileId);
    }

    /**
     * Creates a new file transfer error message.
     *
     * @param senderId     The ID of the local user (who is reporting the error).
     * @param recipientId  The ID of the other peer involved in the transfer.
     * @param fileId       The ID of the file transfer that encountered an error.
     * @param errorMessage A descriptive error message.
     * @return A {@link Message} object of type FILE_TRANSFER_ERROR.
     */
    public Message createFileTransferErrorMessage(String senderId, String recipientId, String fileId, String errorMessage) {
        // For a more structured error, you might send a Map or a dedicated error object
        // For now, sending a simple message, but FileTransferService expects a Map for detailed errors.
        // Let's create a map payload for consistency with how it might be handled.
        Map<String, String> payload = new java.util.HashMap<>();
        payload.put("fileId", fileId);
        payload.put("errorMessage", errorMessage);
        // You could add an "errorCode" field here too if you define a set of error codes.
        payload.put("errorCode", "GENERIC_ERROR"); // Example error code
        return new Message(Message.MessageType.FILE_TRANSFER_ERROR, senderId, recipientId, payload);
    }

    /**
     * Creates a new read receipt message.
     *
     * @param senderId      The ID of the local user (who read the message).
     * @param recipientId   The ID of the original sender of the message being acknowledged.
     * @param readMessageId The ID of the message that was read.
     * @return A {@link Message} object of type READ_RECEIPT.
     */
    public Message createReadReceiptMessage(String senderId, String recipientId, String readMessageId) {
        return new Message(Message.MessageType.READ_RECEIPT, senderId, recipientId, readMessageId);
    }
}
