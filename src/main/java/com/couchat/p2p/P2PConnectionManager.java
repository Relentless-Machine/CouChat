package com.couchat.p2p;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.messaging.MessageService;
import com.couchat.messaging.model.Message;
import com.couchat.security.EncryptionService; // Added import
import com.couchat.p2p.DeviceDiscoveryService.DiscoveredPeer; // Added import

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Manages P2P connections with other peers.
 * This service handles listening for incoming connections and initiating outgoing connections.
 * It uses {@link DeviceDiscoveryService} to find other peers on the network.
 */
@Service
public class P2PConnectionManager {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnectionManager.class);
    private static final int HANDSHAKE_TIMEOUT_MS = 10000;
    private static final String HANDSHAKE_MSG_PEER_ID = "PEER_ID:";
    private static final String HANDSHAKE_MSG_PUBLIC_KEY = "PUBLIC_KEY:";
    private static final String HANDSHAKE_MSG_SESSION_KEY = "SESSION_KEY:";
    private static final String HANDSHAKE_MSG_READY = "READY";

    private final DeviceDiscoveryService deviceDiscoveryService;
    private final EncryptionService encryptionService;
    private final MessageService messageService;
    private final PasskeyAuthService passkeyAuthService;
    private String localPeerId; // To be fetched from PasskeyAuthService

    private ServerSocket serverSocket;
    private final ExecutorService connectionExecutor = Executors.newCachedThreadPool();
    private final ExecutorService incomingConnectionHandlerExecutor = Executors.newSingleThreadExecutor();
    private final ConcurrentHashMap<String, P2PConnection> activeConnections = new ConcurrentHashMap<>();
    private int servicePort;

    /**
     * Constructs a P2PConnectionManager.
     *
     * @param deviceDiscoveryService the service for discovering other peers.
     * @param encryptionService the service for encrypting/decrypting messages.
     * @param messageService the service for processing incoming messages.
     * @param passkeyAuthService the service for obtaining the local peer ID.
     */
    @Autowired
    public P2PConnectionManager(DeviceDiscoveryService deviceDiscoveryService,
                                EncryptionService encryptionService,
                                MessageService messageService,
                                PasskeyAuthService passkeyAuthService) {
        this.deviceDiscoveryService = deviceDiscoveryService;
        this.encryptionService = encryptionService;
        this.messageService = messageService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Initializes the P2PConnectionManager.
     * Fetches the local peer ID and starts listening for incoming P2P connections.
     */
    @PostConstruct
    public void init() {
        this.localPeerId = passkeyAuthService.getLocalPeerId();
        if (this.localPeerId == null || this.localPeerId.isEmpty()) {
            logger.error("P2PConnectionManager cannot initialize: Local Peer ID is not available from PasskeyAuthService.");
            // Application might need to be halted or run in a degraded mode if peer ID is essential.
            return;
        }
        logger.info("P2PConnectionManager initializing with Local Peer ID: {}", this.localPeerId);

        try {
            this.servicePort = deviceDiscoveryService.getLocalServicePort();
            if (this.servicePort <= 0) {
                 this.servicePort = 9090; // Fallback, ensure consistency
                 logger.warn("Service port not explicitly set, defaulting to {}. Ensure this is intended.", this.servicePort);
                 // It might be better to enforce that deviceDiscoveryService provides a valid port
                 // or fail initialization if the port is critical and not available.
                 deviceDiscoveryService.setLocalServicePort(this.servicePort); // Inform discovery service of the port being used
            }

            serverSocket = new ServerSocket(this.servicePort);
            // If port was 0 (dynamic), update discovery service with the actual port
            if (this.servicePort == 0) {
                this.servicePort = serverSocket.getLocalPort();
                deviceDiscoveryService.setLocalServicePort(this.servicePort);
            }
            logger.info("P2PConnectionManager started. Listening for incoming connections on port {}", this.servicePort);

            incomingConnectionHandlerExecutor.execute(this::listenForIncomingConnections);

        } catch (IOException e) {
            logger.error("Failed to start P2PConnectionManager or open ServerSocket on port {}: {}", this.servicePort, e.getMessage(), e);
            // Consider re-throwing or a more robust error handling/application shutdown strategy
        }
    }

    /**
     * Listens for incoming P2P connections.
     * This method runs in a dedicated thread.
     */
    private void listenForIncomingConnections() {
        while (!Thread.currentThread().isInterrupted() && serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept(); // Blocking call
                logger.info("Accepted incoming connection from {}", clientSocket.getRemoteSocketAddress());
                // Set timeout for the entire handshake process for this connection
                clientSocket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
                connectionExecutor.execute(() -> handleIncomingConnection(clientSocket));
            } catch (SocketException se) {
                if (serverSocket.isClosed()) {
                    logger.info("ServerSocket closed, stopping listening for incoming connections.");
                    break;
                }
                logger.error("SocketException while accepting connections: {}", se.getMessage(), se);
            } catch (IOException e) {
                if (!Thread.currentThread().isInterrupted()) {
                    logger.error("IOException while accepting connections: {}", e.getMessage(), e);
                } else {
                    logger.info("Interrupted while waiting for connections, shutting down listener.");
                    break;
                }
            }
        }
        logger.info("Stopped listening for incoming P2P connections.");
    }

    /**
     * Handles an accepted incoming P2P connection.
     * This includes performing a peer ID and public key exchange, then receiving an encrypted session key.
     *
     * @param clientSocket the socket for the incoming connection.
     */
    private void handleIncomingConnection(Socket clientSocket) {
        String remotePeerId = null;
        P2PConnection connection = null;
        try {
            InputStream inputStream = clientSocket.getInputStream();
            OutputStream outputStream = clientSocket.getOutputStream();

            // 1. Receive PeerID from connecting client
            String clientPeerIdMsg = readMessage(inputStream);
            if (clientPeerIdMsg == null || !clientPeerIdMsg.startsWith(HANDSHAKE_MSG_PEER_ID)) {
                logger.warn("Incoming connection: Did not receive valid PeerID. Closing.");
                clientSocket.close();
                return;
            }
            remotePeerId = clientPeerIdMsg.substring(HANDSHAKE_MSG_PEER_ID.length());
            logger.info("Incoming connection from {}: Received PeerID: {}", clientSocket.getRemoteSocketAddress(), remotePeerId);

            // 2. Receive PublicKey from connecting client
            String clientPublicKeyMsg = readMessage(inputStream);
            if (clientPublicKeyMsg == null || !clientPublicKeyMsg.startsWith(HANDSHAKE_MSG_PUBLIC_KEY)) {
                logger.warn("Incoming connection {}: Did not receive PublicKey. Closing.", remotePeerId);
                clientSocket.close();
                return;
            }
            String remotePublicKeyStr = clientPublicKeyMsg.substring(HANDSHAKE_MSG_PUBLIC_KEY.length());
            PublicKey remoteRsaPublicKey = encryptionService.getPublicKeyFromString(remotePublicKeyStr);
            if (remoteRsaPublicKey == null) {
                logger.warn("Incoming connection {}: Invalid PublicKey received. Closing.", remotePeerId);
                clientSocket.close();
                return;
            }
            logger.info("Incoming connection {}: Received PublicKey.", remotePeerId);

            // Prevent duplicate connections
            if (activeConnections.containsKey(remotePeerId)) {
                logger.warn("Peer {} is already connected or connection attempt in progress. Closing new incoming connection from {}.", remotePeerId, clientSocket.getRemoteSocketAddress());
                clientSocket.close();
                return;
            }

            // Create connection object early to manage state, but it's not fully active yet.
            connection = new P2PConnection(
                    this.localPeerId, // Use the fetched localPeerId
                    remotePeerId, clientSocket,
                    this, encryptionService, messageService);
            // Temporarily add to active connections to prevent immediate re-connection attempts
            // If handshake fails, it will be removed.
            activeConnections.put(remotePeerId, connection);

            // 3. Send local PeerID
            sendMessage(outputStream, HANDSHAKE_MSG_PEER_ID + this.localPeerId); // Use the fetched localPeerId
            logger.info("Incoming connection {}: Sent local PeerID.", remotePeerId);

            // 4. Send local PublicKey
            String localPublicKeyStr = encryptionService.getPublicKeyString(encryptionService.getLocalRsaPublicKey());
            sendMessage(outputStream, HANDSHAKE_MSG_PUBLIC_KEY + localPublicKeyStr);
            logger.info("Incoming connection {}: Sent local PublicKey.", remotePeerId);

            // 5. Receive encrypted AES session key from the connecting client (who initiated and generated it)
            String encryptedSessionKeyMsg = readMessage(inputStream);
            if (encryptedSessionKeyMsg == null || !encryptedSessionKeyMsg.startsWith(HANDSHAKE_MSG_SESSION_KEY)) {
                logger.warn("Incoming connection {}: Did not receive SessionKey. Closing.", remotePeerId);
                throw new IOException("SessionKey not received");
            }
            String encryptedAesKeyB64 = encryptedSessionKeyMsg.substring(HANDSHAKE_MSG_SESSION_KEY.length());
            byte[] decryptedAesKeyBytes = encryptionService.decryptWithRsaPrivateKey(encryptedAesKeyB64, encryptionService.getLocalRsaPrivateKey());
            if (decryptedAesKeyBytes == null) {
                logger.warn("Incoming connection {}: Failed to decrypt SessionKey. Closing.", remotePeerId);
                throw new IOException("Failed to decrypt session key");
            }
            SecretKey sessionAesKey = encryptionService.getSecretKeyFromString(Base64.getEncoder().encodeToString(decryptedAesKeyBytes)); // Reconstruct SecretKey
            if (sessionAesKey == null) {
                 logger.warn("Incoming connection {}: Failed to reconstruct SessionKey object. Closing.", remotePeerId);
                throw new IOException("Failed to reconstruct session key object");
            }
            connection.setSessionAesKey(sessionAesKey);
            logger.info("Incoming connection {}: SessionKey received and decrypted.", remotePeerId);

            // 6. Send READY signal
            sendMessage(outputStream, HANDSHAKE_MSG_READY);
            logger.info("Incoming connection {}: Sent READY signal.", remotePeerId);

            connection.setHandshakeComplete();
            connection.startListening(); // Start the dedicated message listener thread for this connection
            clientSocket.setSoTimeout(0); // Reset timeout, connection is now for general message exchange
            logger.info("Successfully completed handshake with incoming peer: {}. Secure P2P connection established.", remotePeerId);

        } catch (SocketTimeoutException e) {
            logger.warn("Timeout during handshake with incoming connection from {}: {}", clientSocket.getRemoteSocketAddress(), e.getMessage());
            closeClientSocketOnError(clientSocket, remotePeerId, connection);
        } catch (IOException e) {
            logger.error("IOException during incoming connection handshake for {}{}: {}",
                (remotePeerId != null ? "peer " + remotePeerId : clientSocket.getRemoteSocketAddress()),
                (e.getMessage().equals("SessionKey not received") || e.getMessage().equals("Failed to decrypt session key") || e.getMessage().equals("Failed to reconstruct session key object") ? "" : " (General I/O error)"),
                e.getMessage());
            closeClientSocketOnError(clientSocket, remotePeerId, connection);
        } catch (Exception e) { // Catch any other unexpected errors during handshake
            logger.error("Unexpected error during incoming handshake with {}: {}",
                         (remotePeerId != null ? remotePeerId : clientSocket.getRemoteSocketAddress()), e.getMessage(), e);
            closeClientSocketOnError(clientSocket, remotePeerId, connection);
        }
    }

    /**
     * Initiates a P2P connection and handshake to a specified peer.
     * This side (initiator) will generate the AES session key.
     *
     * @param peerId The ID of the peer to connect to.
     */
    public void connectToPeer(String peerId) {
        if (peerId == null || peerId.isEmpty()) {
            logger.warn("Cannot connect: Peer ID is null or empty.");
            return;
        }
        if (this.localPeerId == null || this.localPeerId.isEmpty()) {
            logger.error("Cannot connect: Local Peer ID is not available. P2PConnectionManager might not have initialized correctly.");
            return;
        }
        if (peerId.equals(this.localPeerId)) {
            logger.info("Cannot connect to self.");
            return;
        }
        if (activeConnections.containsKey(peerId) && !(activeConnections.get(peerId) instanceof P2PConnection.Placeholder)) {
            logger.info("Already actively connected to peer: {}. Aborting new connection attempt.", peerId);
            return;
        }

        DiscoveredPeer peer = deviceDiscoveryService.getPeerById(peerId);
        if (peer == null) {
            logger.warn("Cannot connect: Peer {} not found in discovered list.", peerId);
            return;
        }

        logger.info("Attempting to connect to peer: {} at {}:{}", peer.getPeerId(), peer.getIpAddress(), peer.getServicePort());

        P2PConnection.Placeholder placeholder;
        try {
            placeholder = new P2PConnection.Placeholder(peerId);
        } catch (IOException e) {
            // This is highly unlikely given the Placeholder constructor with null socket,
            // but required due to method signature.
            logger.error("IOException while creating P2PConnection.Placeholder for peer {}. Aborting connection attempt.", peerId, e);
            return;
        }

        // Use putIfAbsent for placeholder to avoid race conditions if called multiple times quickly.
        // If a real connection or another placeholder is already there, this won't overwrite it.
        boolean proceedWithConnection = activeConnections.putIfAbsent(peerId, placeholder) == null;

        if (!proceedWithConnection) {
            logger.info("Connection attempt to peer {} is already in progress or established. Aborting this attempt.", peerId);
            return;
        }

        connectionExecutor.execute(() -> {
            Socket socket = null;
            P2PConnection connection = null; // Will replace placeholder
            try {
                socket = new Socket(peer.getIpAddress(), peer.getServicePort());
                socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS); // Timeout for handshake
                logger.info("Successfully connected socket to peer {} at {}", peer.getPeerId(), socket.getRemoteSocketAddress());

                OutputStream outputStream = socket.getOutputStream();
                InputStream inputStream = socket.getInputStream();

                // 1. Send local PeerID
                // String localId = deviceDiscoveryService.getLocalPeerId(); // Now using this.localPeerId
                sendMessage(outputStream, HANDSHAKE_MSG_PEER_ID + this.localPeerId);
                logger.info("Outgoing connection {}: Sent local PeerID.", peer.getPeerId());

                // 2. Send local PublicKey
                String localPublicKeyStr = encryptionService.getPublicKeyString(encryptionService.getLocalRsaPublicKey());
                sendMessage(outputStream, HANDSHAKE_MSG_PUBLIC_KEY + localPublicKeyStr);
                logger.info("Outgoing connection {}: Sent local PublicKey.", peer.getPeerId());

                // 3. Receive PeerID from remote
                String remotePeerIdMsg = readMessage(inputStream);
                if (remotePeerIdMsg == null || !remotePeerIdMsg.startsWith(HANDSHAKE_MSG_PEER_ID)) {
                    throw new IOException("Did not receive PeerID from remote peer " + peer.getPeerId());
                }
                String receivedRemotePeerId = remotePeerIdMsg.substring(HANDSHAKE_MSG_PEER_ID.length());
                if (!peer.getPeerId().equals(receivedRemotePeerId)) {
                    throw new IOException("Remote peer ID mismatch. Expected " + peer.getPeerId() + " but got " + receivedRemotePeerId);
                }
                logger.info("Outgoing connection {}: Received remote PeerID: {}", peer.getPeerId(), receivedRemotePeerId);

                // 4. Receive PublicKey from remote
                String remotePublicKeyMsg = readMessage(inputStream);
                if (remotePublicKeyMsg == null || !remotePublicKeyMsg.startsWith(HANDSHAKE_MSG_PUBLIC_KEY)) {
                    throw new IOException("Did not receive PublicKey from remote peer " + peer.getPeerId());
                }
                String remotePublicKeyStr = remotePublicKeyMsg.substring(HANDSHAKE_MSG_PUBLIC_KEY.length());
                PublicKey remoteRsaPublicKey = encryptionService.getPublicKeyFromString(remotePublicKeyStr);
                if (remoteRsaPublicKey == null) {
                    throw new IOException("Invalid PublicKey received from remote peer " + peer.getPeerId());
                }
                logger.info("Outgoing connection {}: Received remote PublicKey.", peer.getPeerId());

                // Create the actual P2PConnection object now that we have the socket
                connection = new P2PConnection(
                        this.localPeerId, // Use the fetched localPeerId
                        peer.getPeerId(),
                        socket,
                        this,
                        encryptionService,
                        messageService);

                // 5. Generate AES session key, encrypt it with remote's RSA public key, and send it
                SecretKey sessionAesKey = encryptionService.generateAesKey();
                if (sessionAesKey == null) {
                    throw new IOException("Failed to generate session AES key for peer " + peer.getPeerId());
                }
                String encryptedAesKeyB64 = encryptionService.encryptWithRsaPublicKey(sessionAesKey.getEncoded(), remoteRsaPublicKey);
                if (encryptedAesKeyB64 == null) {
                    throw new IOException("Failed to encrypt session key for peer " + peer.getPeerId());
                }
                sendMessage(outputStream, HANDSHAKE_MSG_SESSION_KEY + encryptedAesKeyB64);
                connection.setSessionAesKey(sessionAesKey); // Set it for our side
                logger.info("Outgoing connection {}: Generated, encrypted, and sent SessionKey.", peer.getPeerId());

                // 6. Wait for READY signal from remote peer
                String readyMsg = readMessage(inputStream);
                if (readyMsg == null || !readyMsg.equals(HANDSHAKE_MSG_READY)) {
                    throw new IOException("Did not receive READY signal from remote peer " + peer.getPeerId());
                }
                logger.info("Outgoing connection {}: Received READY signal.", peer.getPeerId());

                // Handshake successful, replace placeholder with the actual connection
                P2PConnection oldConnection = activeConnections.put(peer.getPeerId(), connection);
                if (oldConnection != placeholder && oldConnection != null) {
                    logger.warn("Replaced an existing non-placeholder connection for peer {} during outgoing handshake. Closing old one.", peer.getPeerId());
                    oldConnection.close(); // Should not happen if initial checks are correct
                }

                connection.setHandshakeComplete();
                connection.startListening();
                socket.setSoTimeout(0); // Reset timeout
                logger.info("Successfully completed handshake with outgoing peer: {}. Secure P2P connection established.", peer.getPeerId());

            } catch (SocketTimeoutException e) {
                logger.warn("Timeout during handshake with outgoing peer {}: {}", peer.getPeerId(), e.getMessage());
                cleanupFailedConnectionAttempt(socket, peer.getPeerId(), connection, placeholder);
            } catch (IOException e) {
                logger.error("IOException during outgoing connection handshake with peer {}: {}", peer.getPeerId(), e.getMessage(), e);
                cleanupFailedConnectionAttempt(socket, peer.getPeerId(), connection, placeholder);
            } catch (Exception e) { // Catch any other unexpected errors
                logger.error("Unexpected error during outgoing handshake with {}: {}", peer.getPeerId(), e.getMessage(), e);
                cleanupFailedConnectionAttempt(socket, peer.getPeerId(), connection, placeholder);
            }
        });
    }

    private void closeClientSocketOnError(Socket clientSocket, String remotePeerId, P2PConnection connection) {
        if (connection != null) {
            connection.close(); // This will also call removeConnection
        } else if (remotePeerId != null) {
            removeConnection(remotePeerId); // Remove if only peerId was known
        }
        try {
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (IOException ex) {
            logger.error("Error closing client socket after handshake error for {}: {}",
                         (remotePeerId != null ? remotePeerId : clientSocket.getRemoteSocketAddress()), ex.getMessage());
        }
    }

    private void cleanupFailedConnectionAttempt(Socket socket, String peerId, P2PConnection connection, P2PConnection.Placeholder placeholder) {
        if (connection != null) {
            connection.close(); // Will also remove from activeConnections if it was fully added
        }
        // Ensure placeholder is removed if the connection object wasn't created or failed before replacing
        activeConnections.computeIfPresent(peerId, (k, v) -> (v == placeholder || v == connection) ? null : v);

        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ex) {
            logger.error("Error closing socket to peer {} after failed connection attempt: {}", peerId, ex.getMessage());
        }
    }

    private void sendMessage(OutputStream outputStream, String message) throws IOException {
        outputStream.write((message + "\n").getBytes(StandardCharsets.UTF_8)); // Add newline as delimiter
        outputStream.flush();
    }

    private String readMessage(InputStream inputStream) throws IOException {
        byte[] buffer = new byte[4096]; // Max message size for handshake
        int bytesRead = inputStream.read(buffer);
        if (bytesRead > 0) {
            return new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).trim(); // Trim to remove newline
        }
        return null; // Or throw EOFException if appropriate
    }

    /**
     * Removes a connection from the active connections map.
     * This is typically called by {@link P2PConnection#close()}.
     *
     * @param peerId The ID of the peer whose connection is to be removed.
     */
    public void removeConnection(String peerId) {
        if (peerId != null) {
            P2PConnection removedConnection = activeConnections.remove(peerId);
            if (removedConnection != null && !(removedConnection instanceof P2PConnection.Placeholder)) {
                logger.info("Removed P2P connection for peer: {}", peerId);
            }
        }
    }

    /**
     * Sends a message to the specified peer.
     * The message is first serialized and then encrypted before sending.
     *
     * @param peerId  The ID of the recipient peer.
     * @param message The {@link com.couchat.messaging.model.Message} object to send.
     */
    public void sendMessage(String peerId, Message message) { // Changed parameter type to com.couchat.messaging.model.Message
        P2PConnection connection = activeConnections.get(peerId);
        if (connection != null && connection.isActive()) {
            // The P2PConnection's sendMessage method expects a Message object
            // and handles serialization internally before encryption.
            connection.sendMessage(message); // Corrected: Pass the Message object directly
            logger.info("Message of type {} queued for sending to peer {}. Message ID: {}", message.getType(), peerId, message.getMessageId());
        } else {
            logger.warn("Cannot send message to peer {}: No active connection found or connection is not ready. Message ID: {}", peerId, message.getMessageId());
            // TODO: Implement message queuing for offline peers or if connection is temporarily unavailable.
            // This could involve storing the message in a local database and retrying later.
        }
    }

    /**
     * Retrieves a P2PConnection object for a given peer ID.
     * This can be used to check the connection status or for low-level communication.
     *
     * @param peerId The ID of the peer.
     * @return The P2PConnection object, or null if not found.
     */
    public P2PConnection getConnection(String peerId) {
        return activeConnections.get(peerId);
    }

    /**
     * Shuts down the P2PConnectionManager.
     * Closes all active connections and stops listening for new ones.
     */
    @PreDestroy
    public void shutdown() {
        logger.info("Shutting down P2PConnectionManager...");
        incomingConnectionHandlerExecutor.shutdownNow();
        connectionExecutor.shutdownNow();

        activeConnections.values().forEach(conn -> {
            if (!(conn instanceof P2PConnection.Placeholder)) {
                conn.close();
            }
        });
        activeConnections.clear();

        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
                logger.info("ServerSocket closed.");
            } catch (IOException e) {
                logger.error("Error closing ServerSocket: {}", e.getMessage(), e);
            }
        }

        try {
            if (!incomingConnectionHandlerExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                 logger.warn("Incoming connection handler executor did not terminate in time.");
            }
            if (!connectionExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("Connection executor did not terminate in time.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Interrupted during shutdown of executors.");
        }
        logger.info("P2PConnectionManager shut down.");
    }

    // Inner class or separate class to manage an individual P2P connection
    // This is a very basic placeholder. A real implementation would be more complex.
    // static class P2PConnection implements Runnable {
    //     private final String peerId;
    //     private final Socket socket;
    //     private final InputStream inputStream;
    //     private final OutputStream outputStream;
    //     private final P2PConnectionManager manager;
    //     // private final EncryptionService encryptionService;
    //     // private final MessageService messageService;
    //     private volatile boolean running = true;

    //     public P2PConnection(String peerId, Socket socket, P2PConnectionManager manager,
    //                          EncryptionService encryptionService, MessageService messageService) throws IOException {
    //         this.peerId = peerId;
    //         this.socket = socket;
    //         this.inputStream = socket.getInputStream();
    //         this.outputStream = socket.getOutputStream();
    //         this.manager = manager;
    //         // this.encryptionService = encryptionService;
    //         // this.messageService = messageService;
    //     }

    //     public void startListening() {
    //         new Thread(this).start();
    //     }

    //     @Override
    //     public void run() {
    //         try {
    //             // Handshake: send local peerId, receive remote peerId (if not already done)
    //             // String localId = manager.deviceDiscoveryService.getLocalPeerId();
    //             // outputStream.write(localId.getBytes()); // Example
    //             // byte[] buffer = new byte[1024];
    //             // int bytesRead = inputStream.read(buffer);
    //             // String remoteConfirmedPeerId = new String(buffer, 0, bytesRead);
    //             // if (!this.peerId.equals(remoteConfirmedPeerId)) { /* handle error */ }


    //             byte[] buffer = new byte[4096];
    //             int bytesRead;
    //             while (running && (bytesRead = inputStream.read(buffer)) != -1) {
    //                 String rawMessage = new String(buffer, 0, bytesRead);
    //                 // String decryptedMessage = encryptionService.decrypt(rawMessage);
    //                 // messageService.processIncomingMessage(peerId, decryptedMessage);
    //                 logger.info("Received from {}: {}", peerId, rawMessage); // Placeholder
    //             }
    //         } catch (IOException e) {
    //             if (running) { // Avoid logging error if closed intentionally
    //                 logger.error("IOException in P2PConnection for peer {}: {}", peerId, e.getMessage());
    //             }
    //         } finally {
    //             close();
    //         }
    //     }

    //     public void sendMessage(String message) {
    //         try {
    //             // String encryptedMessage = encryptionService.encrypt(message);
    //             // outputStream.write(encryptedMessage.getBytes());
    //             outputStream.write(message.getBytes()); // Placeholder
    //             outputStream.flush();
    //             logger.info("Sent to {}: {}", peerId, message);
    //         } catch (IOException e) {
    //             logger.error("Failed to send message to peer {}: {}", peerId, e.getMessage());
    //             close(); // Close connection on send error
    //         }
    //     }

    //     public void close() {
    //         if (running) {
    //             running = false;
    //             try {
    //                 if (socket != null && !socket.isClosed()) {
    //                     socket.close();
    //                 }
    //                 logger.info("P2PConnection closed for peer: {}", peerId);
    //             } catch (IOException e) {
    //                 logger.error("Error closing P2PConnection socket for peer {}: {}", peerId, e.getMessage());
    //             } finally {
    //                 manager.removeConnection(peerId);
    //             }
    //         }
    //     }
    // }
}
