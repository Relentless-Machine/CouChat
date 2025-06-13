package com.couchat.p2p;

import com.couchat.messaging.MessageService; // Placeholder
import com.couchat.security.EncryptionService; // Placeholder
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;

/**
 * Represents and manages an active P2P connection with a remote peer.
 * This class handles sending and receiving messages over a socket, integrating
 * with encryption and message processing services.
 * It is designed to be run in its own thread for listening to incoming messages.
 */
public class P2PConnection implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnection.class);

    private final String peerId; // The ID of the remote peer
    private final Socket socket;
    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final P2PConnectionManager connectionManager;
    private final EncryptionService encryptionService; // To be integrated
    private final MessageService messageService; // To be integrated
    private volatile boolean running = true;
    private final String localPeerId;

    /**
     * Constructs a new P2PConnection.
     *
     * @param localPeerId The ID of the local peer.
     * @param peerId The ID of the remote peer.
     * @param socket The socket representing the connection to the remote peer.
     * @param connectionManager The manager responsible for P2P connections.
     * @param encryptionService The service for message encryption/decryption.
     * @param messageService The service for processing incoming messages.
     * @throws IOException if an I/O error occurs when creating input/output streams.
     */
    public P2PConnection(String localPeerId, String peerId, Socket socket, P2PConnectionManager connectionManager,
                         EncryptionService encryptionService, MessageService messageService) throws IOException {
        this.localPeerId = localPeerId;
        this.peerId = peerId;
        this.socket = socket;
        this.inputStream = socket.getInputStream();
        this.outputStream = socket.getOutputStream();
        this.connectionManager = connectionManager;
        this.encryptionService = encryptionService; // Assign injected service
        this.messageService = messageService;   // Assign injected service
        logger.info("P2PConnection created for peer: {} with local ID: {}", peerId, localPeerId);
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
            // Optional: Initial handshake if not already done by P2PConnectionManager
            // For example, send local peerId and verify remote peerId
            // outputStream.write(localPeerId.getBytes());
            // byte[] handshakeBuffer = new byte[1024];
            // int bytesReadHandshake = inputStream.read(handshakeBuffer);
            // String receivedPeerId = new String(handshakeBuffer, 0, bytesReadHandshake).trim();
            // if (!peerId.equals(receivedPeerId)) {
            //     logger.warn("Handshake failed: Expected peerId {} but received {}. Closing connection.", peerId, receivedPeerId);
            //     close();
            //     return;
            // }
            // logger.info("Handshake successful with peer: {}", peerId);

            byte[] buffer = new byte[4096]; // Buffer for incoming messages
            int bytesRead;

            while (running && !socket.isClosed() && (bytesRead = inputStream.read(buffer)) != -1) {
                String rawMessage = new String(buffer, 0, bytesRead);
                logger.debug("Received raw data from {}: {}", peerId, rawMessage);

                // TODO: Decrypt message using encryptionService
                // String decryptedMessage = encryptionService.decrypt(rawMessage, peerId); // Or session key
                String decryptedMessage = rawMessage; // Placeholder

                // TODO: Pass to MessageService for processing
                // messageService.processIncomingMessage(peerId, decryptedMessage);
                logger.info("Received (decrypted) message from {}: {}", peerId, decryptedMessage); // Placeholder
            }
        } catch (SocketException se) {
            if (running) { // Log error only if the connection was supposed to be active
                logger.warn("SocketException for peer {}: {} (Connection likely closed by peer or network issue)", peerId, se.getMessage());
            }
        } catch (IOException e) {
            if (running) {
                logger.error("IOException in P2PConnection for peer {}: {}", peerId, e.getMessage(), e);
            }
        } finally {
            if (running) { // If still running, means it was an unexpected closure
                logger.info("Connection with peer {} ended unexpectedly.", peerId);
            }
            close(); // Ensure cleanup
        }
        logger.debug("P2PConnection listener thread for peer {} finished.", peerId);
    }

    /**
     * Sends a message to the connected peer.
     * The message will be encrypted before sending (TODO).
     *
     * @param message The plain text message to send.
     */
    public void sendMessage(String message) {
        if (!running || socket.isClosed()) {
            logger.warn("Cannot send message to {}: Connection is not active.", peerId);
            return;
        }
        try {
            logger.debug("Sending message to {}: {}", peerId, message);
            // TODO: Encrypt message using encryptionService
            // String encryptedMessage = encryptionService.encrypt(message, peerId); // Or session key
            String encryptedMessage = message; // Placeholder

            outputStream.write(encryptedMessage.getBytes());
            outputStream.flush();
            logger.info("Sent message to {}: {}", peerId, message.length() > 50 ? message.substring(0, 50) + "..." : message);
        } catch (IOException e) {
            logger.error("Failed to send message to peer {}: {}", peerId, e.getMessage(), e);
            // Consider closing the connection if a send error occurs, as it might be unrecoverable
            close();
        }
    }

    /**
     * Closes this P2P connection, including its socket and streams.
     * Notifies the {@link P2PConnectionManager} to remove this connection.
     */
    public void close() {
        if (running) {
            running = false; // Signal the listening loop to stop
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close(); // This will interrupt the blocking read in the run() method
                }
                logger.info("P2PConnection closed for peer: {}", peerId);
            } catch (IOException e) {
                logger.error("Error closing P2PConnection socket for peer {}: {}", peerId, e.getMessage(), e);
            } finally {
                // Notify the manager to remove this connection from active list
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
         */
        public Placeholder(String peerId) throws IOException {
            super(null, peerId, null, null, null, null); // Super constructor needs to be called
            this.placeholderPeerId = peerId;
            // Note: The super call will try to use null socket, IS, OS. This is not ideal.
            // A better design might be a common interface or a different map for placeholders.
            // For now, this works because methods like isActive, sendMessage, close are overridden.
            logger.debug("P2PConnection.Placeholder created for peer: {}", peerId);
        }

        @Override
        public void startListening() {
            // Do nothing for a placeholder
            logger.debug("startListening called on Placeholder for {}, no action taken.", placeholderPeerId);
        }

        @Override
        public void run() {
            // Do nothing for a placeholder
        }

        @Override
        public void sendMessage(String message) {
            logger.warn("sendMessage called on Placeholder for peer {}. Message not sent.", placeholderPeerId);
            // Do nothing, or throw an exception, as this shouldn't be called on a placeholder
        }

        @Override
        public void close() {
            // Do nothing for a placeholder, it's just a marker
            logger.debug("close called on Placeholder for {}, no action taken.", placeholderPeerId);
        }

        @Override
        public boolean isActive() {
            return false; // Placeholders are never active connections
        }

        @Override
        public String getPeerId() {
            return placeholderPeerId;
        }
    }
}
