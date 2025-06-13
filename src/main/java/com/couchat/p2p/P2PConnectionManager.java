package com.couchat.p2p;

import com.couchat.p2p.DeviceDiscoveryService.DiscoveredPeer;
import com.couchat.security.EncryptionService; // Placeholder for actual encryption service
import com.couchat.messaging.MessageService; // Placeholder for actual message service

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
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
    private static final int HANDSHAKE_TIMEOUT_MS = 5000; // Timeout for handshake operations

    private final DeviceDiscoveryService deviceDiscoveryService;
    private final EncryptionService encryptionService; // To be integrated
    private final MessageService messageService; // To be integrated

    private ServerSocket serverSocket;
    private final ExecutorService connectionExecutor = Executors.newCachedThreadPool();
    private final ExecutorService incomingConnectionHandlerExecutor = Executors.newSingleThreadExecutor();
    private final ConcurrentHashMap<String, P2PConnection> activeConnections = new ConcurrentHashMap<>();
    private int servicePort;

    /**
     * Constructs a P2PConnectionManager.
     *
     * @param deviceDiscoveryService the service for discovering other peers.
     * @param encryptionService the service for encrypting/decrypting messages (to be integrated).
     * @param messageService the service for processing incoming messages (to be integrated).
     */
    @Autowired
    public P2PConnectionManager(DeviceDiscoveryService deviceDiscoveryService,
                                EncryptionService encryptionService,
                                MessageService messageService) {
        this.deviceDiscoveryService = deviceDiscoveryService;
        this.encryptionService = encryptionService;
        this.messageService = messageService;
    }

    /**
     * Initializes the P2PConnectionManager.
     * Starts listening for incoming P2P connections on the configured service port.
     */
    @PostConstruct
    public void init() {
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
                clientSocket.setSoTimeout(HANDSHAKE_TIMEOUT_MS); // Set timeout for handshake
                logger.info("Accepted incoming connection from {}", clientSocket.getRemoteSocketAddress());
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
     * This includes performing a handshake and establishing a {@link P2PConnection}.
     *
     * @param clientSocket the socket for the incoming connection.
     */
    private void handleIncomingConnection(Socket clientSocket) {
        String remotePeerId = null;
        try {
            InputStream inputStream = clientSocket.getInputStream();
            OutputStream outputStream = clientSocket.getOutputStream();

            // Simplified Handshake: Read remote peer's ID
            // The connecting client should send its peer ID first.
            byte[] buffer = new byte[1024];
            int bytesRead = inputStream.read(buffer);
            if (bytesRead > 0) {
                remotePeerId = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).trim();
                logger.info("Received handshake from incoming peer: {}", remotePeerId);

                // Send local peer ID as confirmation/part of handshake
                outputStream.write(deviceDiscoveryService.getLocalPeerId().getBytes(StandardCharsets.UTF_8));
                outputStream.flush();

                // TODO: Authenticate/validate the peer if necessary.
                // TODO: Perform key exchange using EncryptionService.

                if (activeConnections.containsKey(remotePeerId)) {
                    logger.warn("Peer {} is already connected. Closing new incoming connection from {}.", remotePeerId, clientSocket.getRemoteSocketAddress());
                    clientSocket.close();
                    return;
                }

                P2PConnection connection = new P2PConnection(
                        deviceDiscoveryService.getLocalPeerId(),
                        remotePeerId,
                        clientSocket,
                        this,
                        encryptionService,
                        messageService);
                activeConnections.put(remotePeerId, connection);
                connection.startListening();
                logger.info("Successfully established incoming P2P connection with peer: {}", remotePeerId);
                clientSocket.setSoTimeout(0); // Reset timeout after handshake
            } else {
                logger.warn("Failed to read peer ID from incoming connection from {}. Closing.", clientSocket.getRemoteSocketAddress());
                clientSocket.close();
            }
        } catch (IOException e) {
            logger.error("IOException during incoming connection handling for {}: {}", clientSocket.getRemoteSocketAddress(), e.getMessage(), e);
            if (remotePeerId != null) {
                removeConnection(remotePeerId); // Clean up if partially registered
            }
            try {
                if (!clientSocket.isClosed()) {
                    clientSocket.close();
                }
            } catch (IOException ex) {
                logger.error("Failed to close socket for {}", clientSocket.getRemoteSocketAddress(), ex);
            }
        }
    }

    /**
     * Initiates a P2P connection to a specified peer.
     *
     * @param peerId The ID of the peer to connect to.
     */
    public void connectToPeer(String peerId) {
        if (peerId == null || peerId.isEmpty()) {
            logger.warn("Cannot connect: Peer ID is null or empty.");
            return;
        }
        if (peerId.equals(deviceDiscoveryService.getLocalPeerId())) {
            logger.info("Cannot connect to self.");
            return;
        }
        if (activeConnections.containsKey(peerId)) {
            logger.info("Already connected or attempting to connect to peer: {}", peerId);
            // Optionally, could return the existing connection or a future if connection is in progress
            return;
        }

        DiscoveredPeer peer = deviceDiscoveryService.getPeerById(peerId);
        if (peer == null) {
            logger.warn("Cannot connect: Peer {} not found in discovered list.", peerId);
            return;
        }

        logger.info("Attempting to connect to peer: {} at {}:{}", peer.getPeerId(), peer.getIpAddress(), peer.getServicePort());

        // Placeholder to prevent multiple concurrent attempts to the same peer
        activeConnections.putIfAbsent(peerId, new P2PConnection.Placeholder(peerId)); // Use a placeholder

        connectionExecutor.execute(() -> {
            Socket socket = null;
            try {
                socket = new Socket(peer.getIpAddress(), peer.getServicePort());
                socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS); // Timeout for handshake
                logger.info("Successfully connected socket to peer {} at {}", peer.getPeerId(), socket.getRemoteSocketAddress());

                OutputStream outputStream = socket.getOutputStream();
                InputStream inputStream = socket.getInputStream();

                // Simplified Handshake: Send local peer ID and expect remote peer ID back
                String localId = deviceDiscoveryService.getLocalPeerId();
                outputStream.write(localId.getBytes(StandardCharsets.UTF_8));
                outputStream.flush();
                logger.debug("Sent local peer ID ({}) to {}", localId, peer.getPeerId());

                byte[] buffer = new byte[1024];
                int bytesRead = inputStream.read(buffer);
                if (bytesRead > 0) {
                    String receivedPeerId = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).trim();
                    logger.info("Received handshake confirmation from outgoing peer: {}", receivedPeerId);
                    if (!peer.getPeerId().equals(receivedPeerId)) {
                        logger.warn("Handshake failed with peer {}. Expected ID {} but received {}. Closing connection.",
                                peer.getPeerId(), peer.getPeerId(), receivedPeerId);
                        socket.close();
                        activeConnections.remove(peerId); // Remove placeholder
                        return;
                    }

                    // TODO: Authenticate/validate the peer.
                    // TODO: Perform key exchange using EncryptionService.

                    P2PConnection connection = new P2PConnection(
                            localId,
                            peer.getPeerId(),
                            socket, // Pass the established socket
                            this,
                            encryptionService,
                            messageService);

                    // Replace placeholder with actual connection, or remove if another thread established it
                    P2PConnection existingConnection = activeConnections.put(peer.getPeerId(), connection);
                    if (existingConnection != null && existingConnection != connection && !(existingConnection instanceof P2PConnection.Placeholder)) {
                        logger.warn("Connection to peer {} was established concurrently. Closing this attempt.", peer.getPeerId());
                        connection.close(); // Close this new connection
                        return;
                    }

                    connection.startListening();
                    logger.info("P2P connection established and listening with peer: {}", peer.getPeerId());
                    socket.setSoTimeout(0); // Reset timeout
                } else {
                    logger.warn("Failed to receive handshake confirmation from peer {}. Closing connection.", peer.getPeerId());
                    socket.close();
                    activeConnections.remove(peerId); // Remove placeholder
                }
            } catch (IOException e) {
                logger.error("Failed to connect or handshake with peer {}: {}", peer.getPeerId(), e.getMessage(), e);
                activeConnections.remove(peerId); // Remove placeholder or failed connection
                if (socket != null && !socket.isClosed()) {
                    try {
                        socket.close();
                    } catch (IOException ex) {
                        logger.error("Error closing socket to peer {} after failure: {}", peer.getPeerId(), ex.getMessage());
                    }
                }
            }
        });
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
     * Sends a message to a specified peer.
     *
     * @param peerId The ID of the recipient peer.
     * @param message The message to send.
     */
    public void sendMessage(String peerId, String message) {
        P2PConnection connection = activeConnections.get(peerId);
        if (connection != null && !(connection instanceof P2PConnection.Placeholder) && connection.isActive()) {
            connection.sendMessage(message);
            // logger.info("Message queued for peer {}: {}", peerId, message); // P2PConnection will log actual send
        } else {
            logger.warn("Cannot send message: No active connection to peer {}, or connection is a placeholder.", peerId);
            // TODO: Implement offline message handling/queueing if peer is not connected.
        }
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

