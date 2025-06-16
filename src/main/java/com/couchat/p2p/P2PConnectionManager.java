package com.couchat.p2p;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.messaging.service.MessageService;
import com.couchat.messaging.model.Message;
import com.couchat.security.EncryptionService;
import com.couchat.p2p.DeviceDiscoveryService.DiscoveredPeer;
import com.couchat.transfer.FileTransferService;

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
    private final FileTransferService fileTransferService;
    private final PasskeyAuthService passkeyAuthService;
    private String localPeerId;

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
     * @param fileTransferService the service for file transfers.
     * @param passkeyAuthService the service for obtaining the local peer ID.
     */
    @Autowired
    public P2PConnectionManager(DeviceDiscoveryService deviceDiscoveryService,
                                EncryptionService encryptionService,
                                MessageService messageService,
                                FileTransferService fileTransferService,
                                PasskeyAuthService passkeyAuthService) {
        this.deviceDiscoveryService = deviceDiscoveryService;
        this.encryptionService = encryptionService;
        this.messageService = messageService;
        this.fileTransferService = fileTransferService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Initializes the P2PConnectionManager.
     * Fetches the local peer ID and starts listening for incoming P2P connections.
     */
    @PostConstruct
    public void init() {
        this.localPeerId = passkeyAuthService.getLocalUserId();
        if (this.localPeerId == null || this.localPeerId.isEmpty()) {
            logger.error("P2PConnectionManager cannot initialize: Local User ID is not available from PasskeyAuthService.");
            // Application might need to be halted or run in a degraded mode if peer ID is essential.
            return;
        }
        logger.info("P2PConnectionManager initializing with Local User ID: {}", this.localPeerId);

        try {
            this.servicePort = deviceDiscoveryService.getLocalServicePort();
            if (this.servicePort <= 0) {
                 this.servicePort = 9090; // Fallback, ensure consistency
                 logger.warn("Service port not explicitly set by DeviceDiscoveryService, defaulting to {}. Ensure this is intended.", this.servicePort);
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
                    this, encryptionService, messageService, fileTransferService);

            P2PConnection existing = activeConnections.putIfAbsent(remotePeerId, connection);
            if (existing != null && !(existing instanceof P2PConnection.Placeholder)) {
                logger.warn("Race condition: Peer {} connected concurrently. Closing this incoming attempt.", remotePeerId);
                connection.close(); // Close the newly created one
                return;
            }
            if (existing instanceof P2PConnection.Placeholder) {
                 logger.info("Replacing placeholder for incoming connection from peer {}.", remotePeerId);
                 // The new connection replaces the placeholder implicitly by putIfAbsent if key was present
                 // but if it wasn't (e.g. placeholder removed due to timeout), this putIfAbsent will add it.
                 // If putIfAbsent returned null, it means no placeholder was there, and 'connection' was added.
                 // If it returned the placeholder, 'connection' was NOT added, so we need to put it.
                 if (activeConnections.get(remotePeerId) instanceof P2PConnection.Placeholder) { // Check if placeholder is still there
                    activeConnections.put(remotePeerId, connection); // Explicitly replace placeholder
                 }
            }

            // 3. Send local PeerID
            sendMessage(outputStream, HANDSHAKE_MSG_PEER_ID + this.localPeerId); // Use the fetched localPeerId
            logger.info("Incoming connection {}: Sent local PeerID.", remotePeerId);

            // 4. Send local PublicKey
            String localPublicKeyStr = encryptionService.getPublicKeyString(encryptionService.getLocalRsaPublicKey());
            if (localPublicKeyStr == null) {
                logger.error("Incoming connection {}: Local RSA PublicKey is not available. Cannot complete handshake.", remotePeerId);
                throw new IOException("Local RSA PublicKey not available for handshake.");
            }
            sendMessage(outputStream, HANDSHAKE_MSG_PUBLIC_KEY + localPublicKeyStr);
            logger.info("Incoming connection {}: Sent local PublicKey.", remotePeerId);

            // 5. Generate and send encrypted AES session key
            SecretKey aesSessionKey = encryptionService.generateAesKey();
            byte[] encryptedAesSessionKey = encryptionService.encryptWithRsaPublicKey(aesSessionKey.getEncoded(), remoteRsaPublicKey);
            if (encryptedAesSessionKey == null) {
                logger.error("Incoming connection {}: Failed to encrypt AES session key. Closing.", remotePeerId);
                throw new IOException("Failed to encrypt session key for handshake.");
            }
            sendMessage(outputStream, HANDSHAKE_MSG_SESSION_KEY + Base64.getEncoder().encodeToString(encryptedAesSessionKey));
            logger.info("Incoming connection {}: Sent encrypted AES session key.", remotePeerId);
            connection.setSessionAesKey(aesSessionKey);

            // 6. Receive READY from client
            String clientReadyMsg = readMessage(inputStream);
            if (clientReadyMsg == null || !clientReadyMsg.equals(HANDSHAKE_MSG_READY)) {
                logger.warn("Incoming connection {}: Did not receive READY message. Closing.", remotePeerId);
                throw new IOException("Client did not send READY message.");
            }
            logger.info("Incoming connection {}: Received READY. Handshake successful.", remotePeerId);
            connection.setHandshakeComplete();
            connection.startListening(); // Start listening for messages on this connection

            // Reset timeout to 0 (infinite) for normal operation after handshake
            clientSocket.setSoTimeout(0);

        } catch (SocketTimeoutException ste) {
            logger.warn("Handshake timeout with incoming connection from {}. Peer ID (if known): {}. Error: {}", clientSocket.getRemoteSocketAddress(), remotePeerId, ste.getMessage());
            if (connection != null) connection.close(); else try { clientSocket.close(); } catch (IOException e) {/*ignore*/}
            if (remotePeerId != null) activeConnections.remove(remotePeerId, connection); // Ensure removal if handshake failed partially
        } catch (IOException e) {
            logger.error("IOException during handshake with incoming connection from {}. Peer ID (if known): {}. Error: {}", clientSocket.getRemoteSocketAddress(), remotePeerId, e.getMessage(), e);
            if (connection != null) connection.close(); else try { clientSocket.close(); } catch (IOException ioe) {/*ignore*/}
            if (remotePeerId != null) activeConnections.remove(remotePeerId, connection);
        } catch (Exception e) {
            logger.error("Unexpected error during handshake with incoming connection from {}. Peer ID (if known): {}. Error: {}", clientSocket.getRemoteSocketAddress(), remotePeerId, e.getMessage(), e);
            if (connection != null) connection.close(); else try { clientSocket.close(); } catch (IOException ioe) {/*ignore*/}
            if (remotePeerId != null) activeConnections.remove(remotePeerId, connection);
        }
    }

    /**
     * Initiates a P2P connection and handshake to a specified peer.
     * This side (initiator) will generate the AES session key.
     *
     * @param peerId The ID of the peer to connect to.
     * @return true if the connection attempt was successfully initiated, false otherwise.
     * @throws IllegalStateException if trying to connect to self or already connected.
     */
    public boolean connectToPeer(String peerId) { // Changed return type to boolean
        if (peerId == null || peerId.isEmpty()) {
            logger.warn("Cannot connect: Peer ID is null or empty.");
            return false; // Return false for invalid input
        }
        if (this.localPeerId == null || this.localPeerId.isEmpty()) {
            logger.error("Cannot connect: Local Peer ID is not available. P2PConnectionManager might not have initialized correctly.");
            return false; // Return false if local peer ID is not set
        }
        if (peerId.equals(this.localPeerId)) {
            logger.info("Cannot connect to self.");
            throw new IllegalStateException("Cannot connect to self."); // Throw exception
        }
        if (activeConnections.containsKey(peerId) && !(activeConnections.get(peerId) instanceof P2PConnection.Placeholder)) {
            logger.info("Already actively connected to peer: {}. Aborting new connection attempt.", peerId);
            throw new IllegalStateException("Already connected to peer: " + peerId); // Throw exception
        }

        DiscoveredPeer peer = deviceDiscoveryService.getPeerById(peerId);
        if (peer == null) {
            logger.warn("Cannot connect: Peer {} not found in discovered list.", peerId);
            return false; // Return false if peer not found
        }

        logger.info("Attempting to connect to peer: {} at {}:{}\", peer.getPeerId(), peer.getIpAddress(), peer.getServicePort());

        P2PConnection.Placeholder placeholder;
        try {
            placeholder = new P2PConnection.Placeholder(peerId);
        } catch (IOException e) {
            // This is highly unlikely given the Placeholder constructor with null socket,
            // but required due to method signature.
            logger.error("IOException while creating P2PConnection.Placeholder for peer {}. Aborting connection attempt.", peerId, e);
            return false;
        }

        // Use putIfAbsent for placeholder to avoid race conditions if called multiple times quickly.
        // If a real connection or another placeholder is already there, this won't overwrite it.
        boolean proceedWithConnection = activeConnections.putIfAbsent(peerId, placeholder) == null;

        if (!proceedWithConnection) {
            logger.info("Connection attempt to peer {} is already in progress or established. Aborting this attempt.\", peerId);
            // This case might indicate a race condition or concurrent attempts.
            // If another attempt already placed a placeholder or a real connection,
            // this attempt should not proceed.
            // Depending on desired behavior, could throw an exception or return false.
            // For now, let's consider it a failed initiation from this specific call's perspective.
            return false;
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

                // 5. Receive encrypted AES session key
                String encryptedSessionKeyMsg = readMessage(inputStream);
                if (encryptedSessionKeyMsg == null || !encryptedSessionKeyMsg.startsWith(HANDSHAKE_MSG_SESSION_KEY)) {
                    throw new IOException("Did not receive session key from remote peer " + peer.getPeerId());
                }
                String encryptedSessionKeyB64 = encryptedSessionKeyMsg.substring(HANDSHAKE_MSG_SESSION_KEY.length());
                byte[] decryptedSessionKeyBytes = encryptionService.decryptWithRsaPrivateKey(Base64.getDecoder().decode(encryptedSessionKeyB64));
                if (decryptedSessionKeyBytes == null) {
                    throw new IOException("Failed to decrypt session key from remote peer " + peer.getPeerId());
                }
                SecretKey aesSessionKey = encryptionService.getAesKeyFromBytes(decryptedSessionKeyBytes);
                connection.setSessionAesKey(aesSessionKey);
                logger.info("Outgoing connection {}: Received and decrypted session key.", peer.getPeerId());

                // 6. Send READY to remote
                sendMessage(outputStream, HANDSHAKE_MSG_READY);
                logger.info("Outgoing connection {}: Sent READY. Handshake successful.", peer.getPeerId());
                connection.setHandshakeComplete();
                connection.startListening();

                socket.setSoTimeout(0); // Reset timeout for normal operation

            } catch (SocketTimeoutException ste) {
                logger.warn("Handshake timeout while connecting to peer {}. Error: {}", peer.getPeerId(), ste.getMessage());
                if (connection != null) connection.close(); else if (socket != null) try { socket.close(); } catch (IOException e) {/*ignore*/}
                activeConnections.remove(peer.getPeerId()); // Remove placeholder or failed connection
            } catch (IOException e) {
                logger.error("IOException while connecting to peer {}: {}", peer.getPeerId(), e.getMessage());
                if (connection != null) connection.close(); else if (socket != null) try { socket.close(); } catch (IOException ioe) {/*ignore*/}
                activeConnections.remove(peer.getPeerId());
            } catch (Exception e) {
                logger.error("Unexpected error while connecting to peer {}: {}", peer.getPeerId(), e.getMessage(), e);
                if (connection != null) connection.close(); else if (socket != null) try { socket.close(); } catch (IOException ioe) {/*ignore*/}
                activeConnections.remove(peer.getPeerId());
            }
        });
        return true; // Connection attempt successfully queued
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
        byte[] buffer = new byte[1024]; // Assuming handshake messages are not excessively long
        int bytesRead = inputStream.read(buffer);
        if (bytesRead == -1) {
            return null;
        }
        return new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).trim();
    }

    /**
     * Removes a connection from the active connections map.
     * This is typically called by {@link P2PConnection#close()}.
     *
     * @param peerId The ID of the peer whose connection is to be removed.
     */
    public void removeConnection(String peerId) {
        P2PConnection removedConnection = activeConnections.remove(peerId);
        if (removedConnection != null && !(removedConnection instanceof P2PConnection.Placeholder)) {
            logger.info("Removed connection for peer: {}", peerId);
        } else if (removedConnection instanceof P2PConnection.Placeholder) {
            logger.info("Removed placeholder for peer: {}", peerId);
        }
    }

    /**
     * Sends a message to the specified peer.
     * The message is first serialized and then encrypted before sending.
     *
     * @param peerId  The ID of the recipient peer.
     * @param message The {@link com.couchat.messaging.model.Message} object to send.
     */
    public void sendMessage(String peerId, Message message) {
        P2PConnection connection = activeConnections.get(peerId);
        if (connection != null && connection.isActive() && connection.isHandshakeComplete()) {
            connection.sendMessage(message);
        } else {
            logger.warn("No active or handshake-complete connection to peer: {}. Message not sent: {}", peerId, message.getMessageId());
            // TODO: Implement offline message queuing or error handling
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
        connectionExecutor.shutdown();
        try {
            if (!connectionExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                connectionExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            connectionExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        activeConnections.values().forEach(P2PConnection::close);
        activeConnections.clear();

        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
                logger.info("ServerSocket closed.");
            } catch (IOException e) {
                logger.error("Error closing server socket: {}", e.getMessage(), e);
            }
        }
        logger.info("P2PConnectionManager shut down.");
    }
}
