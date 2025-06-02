package com.couchat.p2p;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class P2PConnectionManagerTest {

    private P2PConnectionManager p2pConnectionManager;
    private static final Logger logger = LoggerFactory.getLogger(P2PConnectionManagerTest.class);

    @BeforeEach
    void setUp() {
        p2pConnectionManager = new P2PConnectionManager();
    }

    @Test
    void testInitiateConnection_Success() {
        String peerAddress = "192.168.1.100";
        logger.info("Testing successful connection initiation to {}", peerAddress);
        p2pConnectionManager.initiateConnection(peerAddress);
        assertTrue(p2pConnectionManager.isConnected(), "Manager should be connected after successful initiation.");
        assertEquals(peerAddress, p2pConnectionManager.getCurrentPeerAddress(), "Current peer address should be set.");
    }

    @Test
    void testInitiateConnection_NullAddress() {
        logger.info("Testing connection initiation with null address.");
        p2pConnectionManager.initiateConnection(null);
        assertFalse(p2pConnectionManager.isConnected(), "Manager should not be connected with null address.");
        assertNull(p2pConnectionManager.getCurrentPeerAddress(), "Peer address should be null.");
    }

    @Test
    void testInitiateConnection_EmptyAddress() {
        logger.info("Testing connection initiation with empty address.");
        p2pConnectionManager.initiateConnection("    ");
        assertFalse(p2pConnectionManager.isConnected(), "Manager should not be connected with empty address.");
        // Depending on implementation, currentPeerAddress might be the empty string or null.
        // The current P2PConnectionManager sets it to null effectively due to the check.
    }

    @Test
    void testSendMessage_WhenConnected() {
        String peerAddress = "192.168.1.101";
        p2pConnectionManager.initiateConnection(peerAddress);
        logger.info("Testing sendMessage when connected to {}", peerAddress);
        assertDoesNotThrow(() -> p2pConnectionManager.sendMessage("Hello Peer!"), "Should not throw when sending a message while connected.");
    }

    @Test
    void testSendMessage_WhenNotConnected() {
        logger.info("Testing sendMessage when not connected.");
        assertDoesNotThrow(() -> p2pConnectionManager.sendMessage("Hello Peer!"), "Should not throw when sending a message while not connected (should log warning).");
        // Further assertions could involve checking logs if a mock logger was injected.
    }

    @Test
    void testSendMessage_NullMessage() {
        String peerAddress = "192.168.1.101";
        p2pConnectionManager.initiateConnection(peerAddress);
        logger.info("Testing sendMessage with null message content to {}", peerAddress);
        assertDoesNotThrow(() -> p2pConnectionManager.sendMessage(null), "Should not throw when sending a null message (should log warning).");
    }

    @Test
    void testSendMessage_EmptyMessage() {
        String peerAddress = "192.168.1.101";
        p2pConnectionManager.initiateConnection(peerAddress);
        logger.info("Testing sendMessage with empty message content to {}", peerAddress);
        assertDoesNotThrow(() -> p2pConnectionManager.sendMessage(""), "Should not throw when sending an empty message (should log warning).");
    }

    @Test
    void testReceiveMessage_WhenConnected() {
        String peerAddress = "192.168.1.102";
        p2pConnectionManager.initiateConnection(peerAddress);
        logger.info("Testing receiveMessage when connected to {}", peerAddress);
        String message = p2pConnectionManager.receiveMessage();
        assertNotNull(message, "Received message should not be null when connected.");
        assertTrue(message.contains(peerAddress), "Simulated message should contain the peer address.");
    }

    @Test
    void testReceiveMessage_WhenNotConnected() {
        logger.info("Testing receiveMessage when not connected.");
        String message = p2pConnectionManager.receiveMessage();
        assertNull(message, "Received message should be null when not connected.");
    }

    @Test
    void testHandleReconnect_WithPreviousAddress() {
        String peerAddress = "192.168.1.103";
        p2pConnectionManager.initiateConnection(peerAddress); // Establish initial connection
        p2pConnectionManager.closeConnection(); // Simulate disconnection
        assertFalse(p2pConnectionManager.isConnected(), "Should be disconnected before reconnect attempt.");

        logger.info("Testing handleReconnect with previous address {}", peerAddress);
        p2pConnectionManager.handleReconnect();
        assertTrue(p2pConnectionManager.isConnected(), "Manager should be connected after successful reconnect.");
        assertEquals(peerAddress, p2pConnectionManager.getCurrentPeerAddress(), "Peer address should be restored after reconnect.");
    }

    @Test
    void testHandleReconnect_WithoutPreviousAddress() {
        logger.info("Testing handleReconnect without a previous address.");
        p2pConnectionManager.handleReconnect();
        assertFalse(p2pConnectionManager.isConnected(), "Manager should remain disconnected if no previous address.");
    }

    @Test
    void testCloseConnection() {
        String peerAddress = "192.168.1.104";
        p2pConnectionManager.initiateConnection(peerAddress);
        assertTrue(p2pConnectionManager.isConnected(), "Manager should be connected before closing.");
        logger.info("Testing closeConnection with peer {}", peerAddress);
        p2pConnectionManager.closeConnection();
        assertFalse(p2pConnectionManager.isConnected(), "Manager should be disconnected after closing.");
        assertNull(p2pConnectionManager.getCurrentPeerAddress(), "Peer address should be null after closing.");
    }

    @Test
    void testCloseConnection_WhenNotConnected() {
        logger.info("Testing closeConnection when already not connected.");
        assertFalse(p2pConnectionManager.isConnected(), "Manager should initially not be connected.");
        assertDoesNotThrow(() -> p2pConnectionManager.closeConnection(), "Closing an already closed connection should not throw.");
        assertFalse(p2pConnectionManager.isConnected(), "Manager should remain disconnected.");
    }
}

