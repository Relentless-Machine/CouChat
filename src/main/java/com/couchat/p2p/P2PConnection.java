package com.couchat.p2p;

import com.couchat.messaging.model.Message;
import com.couchat.messaging.model.FileChunk;
import com.couchat.messaging.model.FileInfo;
import com.couchat.security.EncryptionService;
import com.couchat.messaging.service.MessageService;
import com.couchat.transfer.FileTransferService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Represents and manages an active P2P connection with a remote peer.
 * This class handles sending and receiving messages over a socket, integrating
 * with encryption and message processing services once a secure session is established.
 * It is designed to be run in its own thread for listening to incoming messages.
 */
public class P2PConnection implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnection.class);

    private final String peerId; // The ID of the remote peer
    private final Socket socket;
    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final P2PConnectionManager connectionManager;
    private final EncryptionService encryptionService;
    private final MessageService messageService;
    private final FileTransferService fileTransferService;
    private final ObjectMapper objectMapper;
    private volatile boolean running = true;
    private final String localPeerId;

    // Session-specific security parameters
    private SecretKey sessionAesKey;            // AES key for this session
    private boolean handshakeComplete = false;    // True if key exchange and handshake are done

    /**
     * Constructs a new P2PConnection.
     * This constructor is called after the initial socket connection is made but before
     * the full secure handshake (including key exchange) is necessarily complete.
     * The sessionAesKey and handshakeComplete status will be updated by the P2PConnectionManager.
     *
     * @param localPeerId The ID of the local peer.
     * @param peerId The ID of the remote peer.
     * @param socket The socket representing the connection to the remote peer.
     * @param connectionManager The manager responsible for P2P connections.
     * @param encryptionService The service for message encryption/decryption.
     * @param messageService The service for processing incoming messages.
     * @param fileTransferService The service for handling file transfers.
     * @throws IOException if an I/O error occurs when creating input/output streams.
     */
    public P2PConnection(String localPeerId, String peerId, Socket socket, P2PConnectionManager connectionManager,
                         EncryptionService encryptionService, MessageService messageService,
                         FileTransferService fileTransferService) throws IOException {
        this.localPeerId = localPeerId;
        this.peerId = peerId;
        this.socket = socket;
        this.inputStream = socket.getInputStream();
        this.outputStream = socket.getOutputStream();
        this.connectionManager = connectionManager;
        this.encryptionService = encryptionService;
        this.messageService = messageService;
        this.fileTransferService = fileTransferService;

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        logger.info("P2PConnection instance created for peer: {} with local ID: {}. Waiting for handshake.", peerId, localPeerId);
    }

    /**
     * Sets the AES session key for this connection.
     * This is typically called by {@link P2PConnectionManager} after successful key exchange.
     *
     * @param sessionAesKey The negotiated AES key for encrypting/decrypting messages.
     */
    public void setSessionAesKey(SecretKey sessionAesKey) {
        this.sessionAesKey = sessionAesKey;
        logger.debug("Session AES key set for peer: {}", peerId);
    }

    /**
     * Marks the handshake (including key exchange) as complete for this connection.
     * This is typically called by {@link P2PConnectionManager}.
     */
    public void setHandshakeComplete() {
        this.handshakeComplete = true;
        logger.info("Handshake complete for peer: {}. Secure communication enabled.", peerId);
    }

    /**
     * Checks if the secure handshake and key exchange process is complete.
     *
     * @return true if the handshake is complete, false otherwise.
     */
    public boolean isHandshakeComplete() {
        return handshakeComplete;
    }

    /**
     * Starts a new thread to listen for incoming messages on this connection.
     */
    public void startListening() {
        Thread listenerThread = new Thread(this);
        listenerThread.setName("P2PConnection-Listener-" + peerId);
        listenerThread.start();
    }

    @Override
    public void run() {
        try {
            byte[] buffer = new byte[8192]; // Increased buffer size for potentially larger JSON messages
            int bytesRead;

            while (running && !socket.isClosed() && (bytesRead = inputStream.read(buffer)) != -1) {
                if (!handshakeComplete) {
                    logger.warn("Received data from peer {} before handshake completion. Ignoring.", peerId);
                    continue;
                }

                String rawEncryptedMessageB64 = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                logger.debug("Received raw encrypted data ({} bytes) from {}: {}", bytesRead, peerId, rawEncryptedMessageB64.length() > 100 ? rawEncryptedMessageB64.substring(0,100) + "..." : rawEncryptedMessageB64);

                if (sessionAesKey == null) {
                    logger.error("Handshake complete but session AES key is null for peer {}. Cannot decrypt. Closing connection.", peerId);
                    close();
                    return;
                }

                byte[] decryptedMessageBytes = encryptionService.decryptWithAesKey(rawEncryptedMessageB64, sessionAesKey);

                if (decryptedMessageBytes != null) {
                    String decryptedJsonMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
                    logger.info("Decrypted JSON message from {}: {}", peerId, decryptedJsonMessage.length() > 100 ? decryptedJsonMessage.substring(0,100) + "..." : decryptedJsonMessage);

                    // --- Start of new message processing logic ---
                    try {
                        Message message = objectMapper.readValue(decryptedJsonMessage, Message.class);
                        logger.info("Processing message from peer {}: Type: {}, ID: {}, Timestamp: {}",
                                    peerId, message.getType(), message.getMessageId(), message.getTimestamp());

                        switch (message.getType()) {
                            case TEXT:
                                messageService.receiveTextMessage(message); // New method in new MessageService
                                break;
                            case READ_RECEIPT:
                                messageService.processReadReceipt(message); // New method in new MessageService
                                break;
                            case FILE_INFO:
                                FileInfo fileInfo = objectMapper.convertValue(message.getPayload(), FileInfo.class);
                                fileTransferService.handleIncomingFileInfo(fileInfo, message.getSenderId());
                                break;
                            case FILE_CHUNK:
                                FileChunk fileChunk = objectMapper.convertValue(message.getPayload(), FileChunk.class);
                                fileTransferService.handleIncomingFileChunk(fileChunk, message.getSenderId());
                                break;
                            case FILE_TRANSFER_ACCEPTED:
                                if (message.getPayload() instanceof String) {
                                    String acceptedFileId = (String) message.getPayload();
                                    fileTransferService.handleFileTransferAccepted(acceptedFileId, message.getSenderId());
                                } else {
                                     logger.warn("Received FILE_TRANSFER_ACCEPTED with invalid payload type from peer {}. Payload: {}", peerId, message.getPayload());
                                }
                                break;
                            case FILE_TRANSFER_REJECTED:
                                if (message.getPayload() instanceof String) {
                                    String rejectedFileId = (String) message.getPayload();
                                    // Using existing method in FileTransferService, assuming it logs and updates status
                                    fileTransferService.handleFileTransferErrorMessage(rejectedFileId, message.getSenderId(), "REJECTED", "Transfer rejected by peer");
                                } else {
                                     logger.warn("Received FILE_TRANSFER_REJECTED with invalid payload type from peer {}. Payload: {}", peerId, message.getPayload());
                                }
                                break;
                            case FILE_TRANSFER_CANCELLED:
                                 if (message.getPayload() instanceof String) {
                                    String cancelledFileId = (String) message.getPayload();
                                    fileTransferService.handleFileTransferErrorMessage(cancelledFileId, message.getSenderId(), "CANCELLED", "Transfer cancelled by peer");
                                } else {
                                     logger.warn("Received FILE_TRANSFER_CANCELLED with invalid payload type from peer {}. Payload: {}", peerId, message.getPayload());
                                }
                                break;
                            case FILE_TRANSFER_COMPLETE: // Sender informs receiver that all chunks are sent
                                if (message.getPayload() instanceof String) {
                                    String completedFileId = (String) message.getPayload();
                                    fileTransferService.handleFileTransferCompletedBySender(completedFileId, message.getSenderId());
                                } else {
                                     logger.warn("Received FILE_TRANSFER_COMPLETE with invalid payload type from peer {}. Payload: {}", peerId, message.getPayload());
                                }
                                break;
                            case FILE_TRANSFER_ERROR: // Peer informs of an error in transfer
                                if (message.getPayload() instanceof Map) {
                                    try {
                                        @SuppressWarnings("unchecked")
                                        Map<String, String> errorPayload = (Map<String, String>) message.getPayload();
                                        String errorFileId = errorPayload.get("fileId");
                                        String errorCode = errorPayload.get("errorCode"); // e.g., "CHUNK_MISSING", "IO_ERROR_ON_RECEIVE"
                                        String errorMessageText = errorPayload.get("errorMessage");
                                        fileTransferService.handleFileTransferErrorMessage(errorFileId, message.getSenderId(), errorCode, errorMessageText);
                                    } catch (Exception e) {
                                        logger.error("Error processing FILE_TRANSFER_ERROR payload from peer {}: {}", peerId, message.getPayload(), e);
                                    }
                                } else {
                                    logger.warn("Received FILE_TRANSFER_ERROR with invalid payload type from peer {}. Payload: {}", peerId, message.getPayload());
                                }
                                break;
                            default:
                                logger.warn("Received unhandled message type: {} from peer {}. Message ID: {}",
                                            message.getType(), peerId, message.getMessageId());
                                break;
                        }
                    } catch (JsonProcessingException e) {
                        logger.error("Failed to parse decrypted JSON message from peer {}: {}. Content: {}", peerId, e.getMessage(), decryptedJsonMessage, e);
                    } catch (Exception e) { // Catch-all for other exceptions during message processing
                        logger.error("Unexpected error processing message from peer {}. Message: {}. Error: {}", peerId, decryptedJsonMessage, e.getMessage(), e);
                    }
                    // --- End of new message processing logic ---
                } else {
                    logger.warn("Failed to decrypt message from peer {}. Potentially corrupted or invalid key.", peerId);
                }
            }
        } catch (SocketException se) {
            if (running) {
                logger.warn("SocketException for peer {}: {} (Connection likely closed by peer or network issue)", peerId, se.getMessage());
            }
        } catch (IOException e) {
            if (running) {
                logger.error("IOException in P2PConnection for peer {}: {}", peerId, e.getMessage(), e);
            }
        } finally {
            if (running) {
                logger.info("Connection with peer {} ended unexpectedly.", peerId);
            }
            close();
        }
        logger.debug("P2PConnection listener thread for peer {} finished.", peerId);
    }

    /**
     * Sends a {@link Message} object to the connected peer.
     * The message is first serialized to JSON by {@link MessageService},
     * then encrypted using the session AES key, and finally sent over the socket.
     * If the handshake is not complete or the session key is not available,
     * a warning is logged, and the message is not sent.
     *
     * @param message The {@link Message} object to send.
     */
    public void sendMessage(Message message) {
        if (!running || socket.isClosed()) {
            logger.warn("Cannot send message to {}: Connection is not active.", peerId);
            return;
        }

        if (!handshakeComplete || sessionAesKey == null) {
            logger.warn("Cannot send message to {}: Handshake not complete or session key not available. Message: {}", peerId, message);
            return;
        }

        if (message == null) {
            logger.warn("Cannot send a null message object to peer {}.", peerId);
            return;
        }

        try {
            // Use local ObjectMapper for serialization
            String jsonMessage = objectMapper.writeValueAsString(message);

            logger.debug("Attempting to encrypt and send JSON message to {}: {}", peerId, jsonMessage.length() > 100 ? jsonMessage.substring(0,100)+"..." : jsonMessage);

            String encryptedMessageB64 = encryptionService.encryptWithAesKey(jsonMessage.getBytes(StandardCharsets.UTF_8), sessionAesKey);

            if (encryptedMessageB64 != null) {
                outputStream.write(encryptedMessageB64.getBytes(StandardCharsets.UTF_8));
                outputStream.flush();
                logger.info("Sent encrypted JSON message ({} bytes) to {}", encryptedMessageB64.length(), peerId);
            } else {
                logger.error("Failed to encrypt JSON message for peer {}. Message not sent.", peerId);
            }
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize message to JSON for peer {}: {}. Error: {}", peerId, message, e.getMessage(), e);
        } catch (IOException e) {
            logger.error("IOException while sending message to peer {}: {}", peerId, e.getMessage(), e);
            close();
        } catch (Exception e) {
            logger.error("Unexpected error while sending message to peer {}: {}", peerId, e.getMessage(), e);
        }
    }

    /**
     * Closes this P2P connection, including its socket and streams.
     * Notifies the {@link P2PConnectionManager} to remove this connection.
     */
    public void close() {
        if (running) {
            running = false;
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
                logger.info("P2PConnection closed for peer: {}", peerId);
            } catch (IOException e) {
                logger.error("Error closing P2PConnection socket for peer {}: {}", peerId, e.getMessage(), e);
            } finally {
                if (connectionManager != null) {
                    connectionManager.removeConnection(peerId);
                }
            }
        }
    }

    /**
     * Gets the ID of the remote peer.
     *
     * @return The remote peer's ID.
     */
    public String getPeerId() {
        return peerId;
    }

    /**
     * Checks if the connection is currently active and running.
     *
     * @return true if the connection is active, false otherwise.
     */
    public boolean isActive() {
        return running && socket != null && !socket.isClosed() && socket.isConnected();
    }

    /**
     * A placeholder class used by {@link P2PConnectionManager} to mark a peer ID
     * for which a connection attempt is in progress, helping to prevent concurrent
     * connection attempts to the same peer.
     * This class extends P2PConnection to be storable in the same map but overrides
     * critical methods to indicate it's not a real, active connection.
     */
    static class Placeholder extends P2PConnection {
        private final String placeholderPeerId;

        /**
         * Constructs a Placeholder connection.
         *
         * @param peerId The ID of the peer for which this placeholder is created.
         * @throws IOException if the super constructor throws it (though unlikely with null socket).
         */
        public Placeholder(String peerId) throws IOException {
            super(null, peerId, null, null, null, null, null);
            this.placeholderPeerId = peerId;
            logger.debug("P2PConnection.Placeholder created for peer: {}", peerId);
        }

        @Override
        public void startListening() {
            logger.debug("startListening called on Placeholder for {}, no action taken.", placeholderPeerId);
        }

        @Override
        public void run() {
            // Do nothing for a placeholder
        }

        @Override
        public void sendMessage(Message message) {
            logger.warn("sendMessage called on Placeholder for peer {}. Message not sent.", placeholderPeerId);
        }

        @Override
        public void close() {
            logger.debug("close called on Placeholder for {}, no action taken.", placeholderPeerId);
        }

        @Override
        public boolean isActive() {
            return false;
        }

        @Override
        public String getPeerId() {
            return placeholderPeerId;
        }
    }
}
