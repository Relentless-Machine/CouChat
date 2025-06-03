package com.couchat.p2p;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Integrate with actual NAT traversal (STUN/TURN) libraries
// TODO: Integrate with WireGuard for VPN tunnel establishment

public class P2PConnectionManager implements P2PConnectionInterface {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnectionManager.class);

    private String currentPeerAddress;
    private String lastPeerAddress; // 存储上一次连接的对等地址，用于重连
    private boolean isConnected;

    public P2PConnectionManager() {
        this.isConnected = false;
    }

    @Override
    public void initiateConnection(String peerAddress) {
        logger.info("Attempting to initiate P2P connection with: {}", peerAddress);
        // Placeholder for NAT traversal and connection logic
        // This would involve STUN/TURN client logic and UDP socket setup
        // For WireGuard, this would also involve setting up the tunnel
        if (peerAddress == null || peerAddress.trim().isEmpty()) {
            logger.warn("Cannot initiate connection: peer address is null or empty.");
            this.isConnected = false;
            return;
        }
        this.currentPeerAddress = peerAddress;
        // Simulate connection success for now
        this.isConnected = true;
        logger.info("P2P connection ostensibly established with: {}", peerAddress);
    }

    @Override
    public void handleReconnect() {
        // 首先尝试使用当前地址
        if (this.currentPeerAddress != null && !this.currentPeerAddress.isEmpty()) {
            logger.info("Attempting to reconnect to current peer: {}", this.currentPeerAddress);
            // Placeholder for reconnection logic
            initiateConnection(this.currentPeerAddress); // Re-use initiate logic
        }
        // 如果当前地址为空，尝试使用上次的地址
        else if (this.lastPeerAddress != null && !this.lastPeerAddress.isEmpty()) {
            logger.info("Attempting to reconnect to last peer: {}", this.lastPeerAddress);
            initiateConnection(this.lastPeerAddress);
        }
        else {
            logger.warn("No previous peer address available to reconnect.");
            this.isConnected = false;
        }
    }

    @Override
    public void sendMessage(String message) {
        if (!this.isConnected || this.currentPeerAddress == null) {
            logger.warn("Cannot send message, no active P2P connection or peer address is null.");
            return;
        }
        if (message == null || message.isEmpty()){
            logger.warn("Cannot send an empty message.");
            return;
        }
        logger.info("Sending message to {}: {}", this.currentPeerAddress, message);
        // Placeholder for sending message over P2P (UDP/WireGuard)
        // Actual implementation would involve sending data through the established socket/tunnel
    }

    @Override
    public String receiveMessage() {
        if (!this.isConnected || this.currentPeerAddress == null) {
            logger.warn("Cannot receive message, no active P2P connection or peer address is null.");
            return null;
        }
        // Placeholder for receiving message over P2P (UDP/WireGuard)
        // Actual implementation would involve listening on the socket/tunnel
        String receivedMessage = "Simulated received message from " + this.currentPeerAddress;
        logger.info("Received message: {}", receivedMessage);
        return receivedMessage;
    }

    // Helper method to simulate closing the connection or checking status
    public void closeConnection() {
        if (this.isConnected) { // Only log and change state if actually connected
            logger.info("Closing P2P connection with: {}", this.currentPeerAddress);
            this.lastPeerAddress = this.currentPeerAddress; // 保存当前对等地址到lastPeerAddress
            this.currentPeerAddress = null; // Clear peer address on disconnect to match test expectations
            this.isConnected = false;
        } else {
            logger.info("No active connection to close, or already closed.");
        }
    }

    public boolean isConnected() {
        return isConnected;
    }

    public String getCurrentPeerAddress() {
        return currentPeerAddress;
    }
}

