package com.couchat.p2p;

import com.couchat.messaging.MessageService;
import com.couchat.security.EncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Base64; // Import for Base64 encoding/decoding

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
    private final EncryptionService encryptionService; // For actual encryption/decryption
    private final MessageService messageService;     // For processing decrypted messages
    private volatile boolean running = true;
    private final String localPeerId;

    // Session-specific security parameters
    private SecretKey sessionAesKey;            // AES key for this session
    private boolean handshakeComplete = false;    // True if key exchange and handshake are done
    // remoteRsaPublicKey might be used by manager during handshake, not necessarily stored here long-term
    // unless needed for re-keying or other specific operations within P2PConnection itself.

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
        this.encryptionService = encryptionService;
        this.messageService = messageService;
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
            byte[] buffer = new byte[4096]; // Buffer for incoming messages
            int bytesRead;

            while (running && !socket.isClosed() && (bytesRead = inputStream.read(buffer)) != -1) {
                if (!handshakeComplete) {
                    // This path should ideally not be hit if P2PConnectionManager handles all pre-handshake messages.
                    // However, as a safeguard or if P2PConnection is started before full handshake signal:
                    logger.warn("Received data from peer {} before handshake completion. Ignoring.", peerId);
                    // Or, pass to a specific pre-handshake handler if P2PConnection is involved in handshake steps.
                    // For now, we assume P2PConnectionManager handles handshake messages on its own thread.
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
                    String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
                    logger.info("Decrypted message from {}: {}", peerId, decryptedMessage.length() > 100 ? decryptedMessage.substring(0,100) + "..." : decryptedMessage);
                    messageService.processIncomingMessage(peerId, decryptedMessage); // Process the decrypted message
                } else {
                    logger.warn("Failed to decrypt message from peer {}. Potentially corrupted or invalid key.", peerId);
                    // Consider policies for handling decryption failures (e.g., terminate connection after N failures)
                }
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
     * If the handshake is complete and a session key is available, the message will be encrypted.
     * Otherwise, a warning is logged, and the message is not sent.
     *
     * @param message The plain text message to send.
     */
    public void sendMessage(String message) {
        if (!running || socket.isClosed()) {
            logger.warn("Cannot send message to {}: Connection is not active.", peerId);
            return;
        }

        if (!handshakeComplete || sessionAesKey == null) {
            logger.warn("Cannot send message to {}: Handshake not complete or session key not available.", peerId);
            return;
        }

        try {
            logger.debug("Attempting to encrypt and send message to {}: {}", peerId, message.length() > 50 ? message.substring(0, 50) + "..." : message);

            // Encrypt the message using the session AES key
            // encryptWithAesKey returns a Base64 encoded string directly
            String encryptedMessageB64 = encryptionService.encryptWithAesKey(message.getBytes(StandardCharsets.UTF_8), sessionAesKey);

            if (encryptedMessageB64 != null) {
                // Send the Base64 encoded encrypted message as bytes
                outputStream.write(encryptedMessageB64.getBytes(StandardCharsets.UTF_8));
                outputStream.flush();
                logger.info("Sent encrypted message ({} bytes) to {}", encryptedMessageB64.length(), peerId);
            } else {
                logger.error("Failed to encrypt message for peer {}. Message not sent.", peerId);
            }
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
         * @throws IOException if the super constructor throws it (though unlikely with null socket).
         */
        public Placeholder(String peerId) throws IOException {
            super(null, peerId, null, null, null, null);
            this.placeholderPeerId = peerId;
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
