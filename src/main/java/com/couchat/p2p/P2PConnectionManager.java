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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy; // Ensure @Lazy is imported
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
    private final MessageService messageService; // Keep this as is for now, will be used by P2PConnection
    private final FileTransferService fileTransferService;
    private final PasskeyAuthService passkeyAuthService;
    private String localPeerId;

    private ServerSocket serverSocket;
    private final ExecutorService connectionExecutor = Executors.newCachedThreadPool();
    private final ExecutorService incomingConnectionHandlerExecutor = Executors.newSingleThreadExecutor();
    private final ConcurrentHashMap<String, P2PConnection> activeConnections = new ConcurrentHashMap<>();
    private int servicePort;
    private volatile boolean isListeningStarted = false;

    @Value("${p2p.service.port:9091}") // Changed default port from 9090 to 9091
    private int configuredServicePort;

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
    public P2PConnectionManager(@Lazy DeviceDiscoveryService deviceDiscoveryService, // Added @Lazy
                                EncryptionService encryptionService,
                                @Lazy MessageService messageService, // Added @Lazy here
                                @Lazy FileTransferService fileTransferService, // Added @Lazy
                                @Lazy PasskeyAuthService passkeyAuthService) { // Added @Lazy
        this.deviceDiscoveryService = deviceDiscoveryService;
        this.encryptionService = encryptionService;
        this.messageService = messageService; // Initialize MessageService
        this.fileTransferService = fileTransferService;
        this.passkeyAuthService = passkeyAuthService;
        logger.debug("P2PConnectionManager initialized with potentially lazy DeviceDiscoveryService, FileTransferService, and PasskeyAuthService."); // Updated log message
    }

    /**
     * Initializes the P2PConnectionManager.
     * Does not start listening immediately; waits for PasskeyAuthService.
     */
    @PostConstruct
    public void init() {
        // Do not start listening or get peer ID here.
        // PasskeyAuthService will call startListening() when ready.
        logger.info("P2PConnectionManager initialized. Waiting for authentication to start listening.");
    }

    /**
     * Starts the P2P listening service. Called by PasskeyAuthService after authentication.
     */
    public synchronized void startListening() {
        if (isListeningStarted) {
            logger.info("P2P listening already started.");
            return;
        }
        if (!passkeyAuthService.isAuthenticated() || passkeyAuthService.getLocalUserId() == null) {
            logger.warn("Attempted to start P2P listening, but user is not authenticated or local user ID is null.");
            return;
        }

        this.localPeerId = passkeyAuthService.getLocalUserId();
        logger.info("Starting P2P Connection Manager listening for Peer ID: {}", this.localPeerId);

        try {
            serverSocket = new ServerSocket(configuredServicePort); // Use configured port
            this.servicePort = serverSocket.getLocalPort(); // Get actual port (useful if configuredPort was 0)

            if (deviceDiscoveryService != null) {
                deviceDiscoveryService.setLocalServicePort(this.servicePort);
            } else {
                logger.warn("DeviceDiscoveryService is null in P2PConnectionManager. Cannot set its local service port.");
            }

            logger.info("P2PConnectionManager started. Listening for incoming connections on port {}", this.servicePort);
            incomingConnectionHandlerExecutor.execute(this::listenForIncomingConnections);
            isListeningStarted = true;
            logger.info("P2PConnectionManager listening tasks started successfully.");

        } catch (IOException e) {
            logger.error("Failed to start P2PConnectionManager ServerSocket on port {}: {}", configuredServicePort, e.getMessage(), e);
            isListeningStarted = false; // Reset flag
        }
    }


    /**
     * Listens for incoming P2P connections.
     * This method runs in a dedicated thread.
     */
    private void listenForIncomingConnections() {
        if (!isListeningStarted) {
             logger.info("P2P listening not started. Incoming connection listener will not run.");
            return;
        }
        while (!Thread.currentThread().isInterrupted() && serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept(); // Blocking call
                logger.info("Accepted incoming connection from {}", clientSocket.getRemoteSocketAddress());
                clientSocket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
                connectionExecutor.execute(() -> handleIncomingConnection(clientSocket));
            } catch (SocketException se) {
                if (serverSocket != null && serverSocket.isClosed()) {
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
        if (!isListeningStarted || localPeerId == null) {
            logger.warn("P2P manager not fully started or localPeerId not set. Cannot handle incoming connection from {}", clientSocket.getRemoteSocketAddress());
            try {
                clientSocket.close();
            } catch (IOException e) {
                logger.warn("Error closing socket during early exit from handleIncomingConnection", e);
            }
            return;
        }
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
            logger.info("Incoming connection {}: Received raw PublicKey string: [{}]. Length: {}", remotePeerId, remotePublicKeyStr, remotePublicKeyStr.length()); // Added detailed log
            PublicKey remoteRsaPublicKey = encryptionService.getPublicKeyFromString(remotePublicKeyStr);
            if (remoteRsaPublicKey == null) {
                logger.warn("Incoming connection {}: Invalid PublicKey received. Closing.", remotePeerId);
                clientSocket.close();
                return;
            }
            logger.info("Incoming connection {}: Received PublicKey.", remotePeerId);

            // Handle simultaneous connection attempts (tie-breaking)
            P2PConnection existingEntry = activeConnections.get(remotePeerId);
            if (existingEntry != null) {
                if (existingEntry instanceof P2PConnection.Placeholder) {
                    // This node (acceptor of this incoming socket) is also trying to connect to the remote peer.
                    logger.info("Simultaneous connection attempt detected with peer {}. Local is acceptor, remote is initiator of this specific socket. Performing tie-breaking.", remotePeerId);
                    // Tie-breaking rule: The peer with the lexicographically smaller PeerID lets its outgoing connection attempt proceed.
                    // The peer with the larger PeerID drops its outgoing attempt and accepts the incoming one.
                    if (this.localPeerId.compareTo(remotePeerId) < 0) {
                        // Local PeerID is smaller. This node's outgoing attempt (represented by the placeholder) takes precedence.
                        // So, we reject this incoming connection and let our outgoing attempt continue.
                        logger.info("Tie-breaking: Local PeerID ({}) is smaller than Remote PeerID ({}). Rejecting incoming connection, local outgoing attempt will continue.", this.localPeerId, remotePeerId);
                        try { clientSocket.close(); } catch (IOException e) { logger.warn("Error closing incoming socket for peer {} during tie-breaking (local wins).", remotePeerId, e); }
                        return; // Abort handling this incoming connection.
                    } else if (this.localPeerId.compareTo(remotePeerId) > 0) {
                        // Local PeerID is larger. This node should drop its outgoing attempt (the placeholder)
                        // and accept this incoming connection.
                        logger.info("Tie-breaking: Local PeerID ({}) is larger than Remote PeerID ({}). Accepting incoming, cancelling local outgoing placeholder.", this.localPeerId, remotePeerId);
                        P2PConnection removedPlaceholder = activeConnections.remove(remotePeerId); // Remove our outgoing placeholder.
                        if (removedPlaceholder instanceof P2PConnection.Placeholder) {
                            logger.info("Successfully removed outgoing placeholder for peer {} to accept incoming connection.", remotePeerId);
                            // The placeholder itself doesn't have a task to cancel, the task in connectToPeer will eventually find no placeholder or a new connection.
                        } else if (removedPlaceholder != null) { // Should ideally not be a full connection if placeholder logic was right
                            logger.warn("Removed a non-placeholder entry for peer {} during tie-breaking (local yields). Entry was: {}. Closing it.", remotePeerId, removedPlaceholder.getClass().getName());
                            removedPlaceholder.close(); // Close it just in case.
                        }
                        // Proceed to establish this incoming connection. 'existingEntry' is no longer the definitive state.
                    } else {
                        // PeerIDs are identical - this should ideally not happen if PeerIDs are globally unique.
                        // Arbitrarily close incoming to prevent potential issues and log an error.
                        logger.error("CRITICAL: Simultaneous connection attempt with peer {} but PeerIDs are identical! This should not happen. Closing incoming connection.", remotePeerId);
                        try { clientSocket.close(); } catch (IOException e) { logger.warn("Error closing incoming socket for peer {} due to identical PeerIDs in tie-breaking.", remotePeerId, e); }
                        return;
                    }
                } else { // existingEntry is a full, active P2PConnection
                    logger.warn("Peer {} is already actively connected. Closing new duplicate incoming connection from {}.", remotePeerId, clientSocket.getRemoteSocketAddress());
                    try { clientSocket.close(); } catch (IOException e) { logger.warn("Error closing incoming socket for already actively connected peer {}.", remotePeerId, e); }
                    return;
                }
            }

            // If we reach here, there was no existing connection, or a placeholder was handled by tie-breaking.
            // Create a new P2PConnection object for this incoming connection.
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

        // Check if an active, handshake-complete connection already exists.
        P2PConnection existingConnection = activeConnections.get(peerId);
        if (existingConnection != null && !(existingConnection instanceof P2PConnection.Placeholder) && existingConnection.isHandshakeComplete()) {
            logger.info("Attempt to connect to peer {} but an active and handshake-complete connection already exists. No action needed, returning success.", peerId);
            return true; // Indicate success as the desired state (connected) is already met.
        }
        // If existingConnection is a Placeholder, the putIfAbsent logic below will handle it by returning false from proceedWithConnection if placeholder is already there by this thread or another.
        // If existingConnection is not null, not a placeholder, but also not handshake-complete,
        // the current logic will also proceed to the putIfAbsent.
        // This means if a previous attempt created a P2PConnection object that didn't complete handshake and wasn't cleared,
        // this new attempt might be blocked if that old P2PConnection object is still in activeConnections.
        // The `proceedWithConnection = activeConnections.putIfAbsent(peerId, placeholder) == null;` line is key here.
        // If an old, non-placeholder, non-handshake-complete connection is there, putIfAbsent will return it, and proceedWithConnection will be false.

        DiscoveredPeer peer = deviceDiscoveryService.getPeerById(peerId);
        if (peer == null) {
            logger.warn("Cannot connect: Peer {} not found in discovered list.", peerId);
            return false; // Return false if peer not found
        }

        logger.info("Attempting to connect to peer: {} at {}:{}", peer.getPeerId(), peer.getIpAddress(), peer.getServicePort());

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
            logger.info("Connection attempt to peer {} is already in progress or established. Aborting this attempt.", peerId);
            // This case might indicate a race condition or concurrent attempts.
            // If another attempt already placed a placeholder or a real connection,
            // this attempt should not proceed.
            // Depending on desired behavior, could throw an exception or return false.
            // For now, let's consider it a failed initiation from this specific call's perspective.
            return false;
        }

        connectionExecutor.execute(() -> {
            Socket socket = null;
            P2PConnection actualConnection = null; // Will hold the actual P2PConnection object

            try {
                socket = new Socket(peer.getIpAddress(), peer.getServicePort());
                socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS); // Set timeout for handshake operations
                logger.info("Successfully connected socket to peer {} at {}", peer.getPeerId(), socket.getRemoteSocketAddress());

                // Create the actual P2PConnection object for this outgoing connection.
                // this.localPeerId is crucial here; it must be non-null for the handshake to succeed.
                // The P2PConnection constructor logs if this.localPeerId is null.
                // Corrected constructor call to include this.localPeerId as the first argument.
                actualConnection = new P2PConnection(this.localPeerId, peer.getPeerId(), socket, this, encryptionService, messageService, fileTransferService);

                // Replace the placeholder in activeConnections with the actual connection object.
                // A P2PConnection.Placeholder is expected to be present, put by putIfAbsent earlier.
                Object currentEntry = activeConnections.get(peer.getPeerId());
                if (currentEntry instanceof P2PConnection.Placeholder) {
                    // Attempt to atomically replace the placeholder with the actual connection.
                    if (!activeConnections.replace(peer.getPeerId(), (P2PConnection.Placeholder)currentEntry, actualConnection)) {
                        // If replacement fails, it means the entry was changed by another thread between get and replace.
                        logger.warn("Failed to replace placeholder for peer {} due to concurrent modification. Closing this connection attempt.", peer.getPeerId());
                        actualConnection.close(); // Close the newly created but now orphaned connection.
                        return; // Abort this connection attempt.
                    }
                    logger.info("Successfully replaced placeholder with actual connection for peer {}.", peer.getPeerId());
                } else {
                    // If it's not a placeholder (or null), there's an issue with connection management logic.
                    // This might happen if the placeholder was removed, or if proceedWithConnection logic was flawed.
                    logger.error("Expected a placeholder for peer {} but found {}. Closing this connection attempt.", peer.getPeerId(), currentEntry);
                    if(actualConnection != null) actualConnection.close(); // Close the newly created connection if it exists.
                    return; // Abort.
                }

                // Get streams directly from the socket, not from actualConnection.
                OutputStream outputStream = socket.getOutputStream(); // Use the socket's stream
                InputStream inputStream = socket.getInputStream();   // Use the socket's stream

                // 1. Send local PeerID
                // this.localPeerId is critical for the remote peer to identify this node.
                sendMessage(outputStream, HANDSHAKE_MSG_PEER_ID + this.localPeerId);
                logger.info("Outgoing connection {}: Sent local PeerID.", peer.getPeerId());

                // 2. Send local PublicKey
                String localPublicKeyStr = encryptionService.getPublicKeyString(encryptionService.getLocalRsaPublicKey());
                sendMessage(outputStream, HANDSHAKE_MSG_PUBLIC_KEY + localPublicKeyStr);
                logger.info("Outgoing connection {}: Sent local PublicKey.", peer.getPeerId());

                // 3. Receive PeerID from remote
                // Expecting a message prefixed with HANDSHAKE_MSG_PEER_ID followed by the remote peer ID.
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
                // Expecting a message prefixed with HANDSHAKE_MSG_PUBLIC_KEY followed by the Base64 encoded public key string.
                String remotePublicKeyMsg = readMessage(inputStream);
                if (remotePublicKeyMsg == null || !remotePublicKeyMsg.startsWith(HANDSHAKE_MSG_PUBLIC_KEY)) {
                    throw new IOException("Did not receive PublicKey from remote peer " + peer.getPeerId());
                }
                String remotePublicKeyStr = remotePublicKeyMsg.substring(HANDSHAKE_MSG_PUBLIC_KEY.length());
                logger.info("Outgoing connection {}: Received raw PublicKey string from remote: [{}]. Length: {}", peer.getPeerId(), remotePublicKeyStr, remotePublicKeyStr.length());
                PublicKey remoteRsaPublicKey = encryptionService.getPublicKeyFromString(remotePublicKeyStr);
                if (remoteRsaPublicKey == null) {
                    throw new IOException("Invalid PublicKey received from remote peer " + peer.getPeerId());
                }
                logger.info("Outgoing connection {}: Received remote PublicKey.", peer.getPeerId());

                // 5. Receive encrypted AES session key
                // Expecting a message prefixed with HANDSHAKE_MSG_SESSION_KEY followed by the Base64 encoded, RSA encrypted AES session key.
                // This node (initiator) receives the session key, which was generated and encrypted by the remote peer (acceptor).
                String encryptedSessionKeyMsg = readMessage(inputStream);
                if (encryptedSessionKeyMsg == null || !encryptedSessionKeyMsg.startsWith(HANDSHAKE_MSG_SESSION_KEY)) {
                    throw new IOException("Did not receive session key from remote peer " + peer.getPeerId());
                }
                String encryptedSessionKeyB64 = encryptedSessionKeyMsg.substring(HANDSHAKE_MSG_SESSION_KEY.length());
                // Decrypt the session key using this node's RSA private key.
                byte[] decryptedSessionKeyBytes = encryptionService.decryptWithRsaPrivateKey(Base64.getDecoder().decode(encryptedSessionKeyB64));
                if (decryptedSessionKeyBytes == null) {
                    throw new IOException("Failed to decrypt session key from remote peer " + peer.getPeerId());
                }
                SecretKey aesSessionKey = encryptionService.getAesKeyFromBytes(decryptedSessionKeyBytes);

                actualConnection.setSessionAesKey(aesSessionKey); // Set the decrypted AES session key on the connection object.
                logger.info("Outgoing connection {}: Received and decrypted session key.", peer.getPeerId());

                // 6. Send READY to remote
                // Signal that this node has completed its part of the handshake and is ready for P2P communication.
                sendMessage(outputStream, HANDSHAKE_MSG_READY);
                logger.info("Outgoing connection {}: Sent READY. Handshake successful.", peer.getPeerId());
                actualConnection.setHandshakeComplete(); // Mark the connection as handshake complete.
                actualConnection.startListening();       // Start the dedicated listener thread for this connection.

                socket.setSoTimeout(0); // Reset socket timeout to 0 (infinite) for normal operation after successful handshake.

            } catch (SocketTimeoutException ste) {
                // Handle cases where a socket operation times out during the handshake (e.g., readMessage).
                logger.warn("Handshake timeout while connecting to peer {}. Error: {}", peer.getPeerId(), ste.getMessage());
                // Close the connection if it was partially formed or the socket if it was created.
                if (actualConnection != null) actualConnection.close(); else if (socket != null) try { socket.close(); } catch (IOException e) {/*ignore socket close error*/}
                // Remove the connection or its placeholder from activeConnections to allow future attempts.
                // P2PConnection.close() should ideally handle its removal from activeConnections.
                // This is a fallback or ensures placeholder removal if actualConnection was never fully established and put.
                activeConnections.remove(peer.getPeerId());
            } catch (IOException e) {
                // Handle general I/O errors during the connection or handshake process (e.g., network issues, stream errors).
                logger.error("IOException while connecting to peer {}: {}", peer.getPeerId(), e.getMessage());
                if (actualConnection != null) actualConnection.close(); else if (socket != null) try { socket.close(); } catch (IOException ioe) {/*ignore socket close error*/}
                activeConnections.remove(peer.getPeerId()); // Ensure cleanup from active connections.
            } catch (Exception e) {
                // Catch any other unexpected exceptions during the connection attempt to prevent thread death.
                logger.error("Unexpected error while connecting to peer {}: {}", peer.getPeerId(), e.getMessage(), e);
                if (actualConnection != null) actualConnection.close(); else if (socket != null) try { socket.close(); } catch (IOException ioe) {/*ignore socket close error*/}
                activeConnections.remove(peer.getPeerId()); // Ensure cleanup.
            }
        });
        return true; // Indicate that the connection attempt has been successfully queued for execution.
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
        byte[] buffer = new byte[2048]; // Increased buffer size for potentially longer keys
        int bytesRead = inputStream.read(buffer);
        if (bytesRead == -1) {
            logger.warn("readMessage: End of stream reached.");
            return null;
        }
        // Log raw bytes before converting to string, to inspect for non-printable chars
        // logger.debug("readMessage: Raw bytes read: {}", new String(buffer, 0, bytesRead, StandardCharsets.ISO_8859_1)); // Example: ISO_8859_1 to see all bytes
        String rawMessage = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
        logger.debug("readMessage: Raw message received before trim: [{}], length: {}", rawMessage, rawMessage.length());
        String trimmedMessage = rawMessage.trim();
        logger.debug("readMessage: Trimmed message: [{}], length: {}", trimmedMessage, trimmedMessage.length());
        return trimmedMessage;
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
        isListeningStarted = false; // Stop new operations

        incomingConnectionHandlerExecutor.shutdown();
        connectionExecutor.shutdown();
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                logger.info("ServerSocket closed.");
            }
            if (!incomingConnectionHandlerExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                incomingConnectionHandlerExecutor.shutdownNow();
            }
            if (!connectionExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                connectionExecutor.shutdownNow();
            }
        } catch (IOException e) {
            logger.error("Error closing server socket during shutdown", e);
        } catch (InterruptedException e) {
            logger.error("Interrupted during shutdown", e);
            Thread.currentThread().interrupt();
        }

        activeConnections.values().forEach(P2PConnection::close);
        activeConnections.clear();
        logger.info("All active P2P connections closed. P2PConnectionManager shut down.");
    }
}
