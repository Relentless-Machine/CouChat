package com.couchat.p2p;

import org.ice4j.TransportAddress;
import org.ice4j.ice.IceProcessingState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for {@link P2PConnectionManager} focusing on STUN discovery with ice4j.
 * Note: These tests may involve actual network operations for STUN and can be
 * affected by network conditions or STUN server availability.
 */
@ExtendWith(MockitoExtension.class)
public class P2PConnectionManagerTest {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnectionManagerTest.class);
    private P2PConnectionManager p2pConnectionManager;
    private static final String TEST_PEER_ADDRESS = "dummy.peer.address"; // Used for non-STUN tests or as a placeholder
    private static final int STUN_DISCOVERY_TIMEOUT_SECONDS = 10; // Reverted timeout
    private static final long POLLING_INTERVAL_MS = 300;

    @BeforeEach
    void setUp() {
        logger.info("Setting up P2PConnectionManagerTest...");
        p2pConnectionManager = new P2PConnectionManager();
        // Allow some time for the ICE Agent to initialize, if necessary.
        // This might be crucial if initialization involves asynchronous operations.
        try {
            Thread.sleep(200); // Small delay for iceAgent initialization
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error("Sleep interrupted during setup", e);
        }
        logger.info("P2PConnectionManager instance created for testing.");
    }

    @AfterEach
    void tearDown() {
        logger.info("Tearing down P2PConnectionManagerTest...");
        if (p2pConnectionManager != null) {
            p2pConnectionManager.closeConnection();
            logger.info("P2PConnectionManager connection closed.");
        }
        p2pConnectionManager = null;
    }

    @Test
    void simpleSurefireCheck() {
        logger.info("Executing simpleSurefireCheck...");
        assertTrue(true, "This simple test should always pass.");
        logger.info("simpleSurefireCheck executed.");
    }

    @Test
    @Timeout(value = STUN_DISCOVERY_TIMEOUT_SECONDS, unit = TimeUnit.SECONDS)
    void testInitiateConnection_DiscoversPublicAddress_Async() throws InterruptedException {
        logger.info("Testing STUN public address discovery (asynchronous)...");
        // Assume network is available for STUN
        assumeTrue(isNetworkAvailable(), "Network connectivity is required for STUN discovery test.");

        p2pConnectionManager.initiateConnection(TEST_PEER_ADDRESS); // Peer address is nominal for STUN discovery

        long startTime = System.currentTimeMillis();
        boolean conditionMet = false;
        IceProcessingState finalIceState = null;

        while (System.currentTimeMillis() - startTime < TimeUnit.SECONDS.toMillis(STUN_DISCOVERY_TIMEOUT_SECONDS)) {
            if (p2pConnectionManager.getIceAgent() != null) {
                 finalIceState = p2pConnectionManager.getIceAgent().getState();
                 logger.debug("Polling: Current ICE state: {}, isConnected: {}, publicAddress: {}",
                             finalIceState, p2pConnectionManager.isConnected(), p2pConnectionManager.getPublicStunAddress());
            } else {
                 logger.warn("Polling: ICE Agent is null.");
                 finalIceState = null;
            }

            if (p2pConnectionManager.isConnected() && p2pConnectionManager.getPublicStunAddress() != null) {
                conditionMet = true;
                logger.info("STUN discovery successful. isConnected: true, publicAddress: {}", p2pConnectionManager.getPublicStunAddress());
                break;
            }

            if (p2pConnectionManager.getIceAgent() != null && IceProcessingState.FAILED.equals(finalIceState)) {
                logger.error("ICE processing failed definitively.");
                break;
            }
            Thread.sleep(POLLING_INTERVAL_MS);
        }

        if (p2pConnectionManager.getIceAgent() != null && finalIceState == null) {
             finalIceState = p2pConnectionManager.getIceAgent().getState();
        }

        assertTrue(conditionMet, "STUN discovery should result in isConnected() being true and publicAddress being non-null. Final ICE State: " + finalIceState + ", isConnected: " + p2pConnectionManager.isConnected() + ", publicAddress: " + p2pConnectionManager.getPublicStunAddress());

        TransportAddress publicStunAddress = p2pConnectionManager.getPublicStunAddress();
        assertNotNull(publicStunAddress, "Public STUN address should not be null after successful discovery (checked again).");
        logger.info("Discovered public STUN address: {}:{}", publicStunAddress.getHostAddress(), publicStunAddress.getPort());
        // Basic validation of the address (e.g., not a loopback or private IP)
        // This is a heuristic and might need adjustment based on network environment.
        try {
            InetAddress addr = InetAddress.getByName(publicStunAddress.getHostAddress());
            assertFalse(addr.isLoopbackAddress(), "Public STUN address should not be a loopback address.");
            assertFalse(addr.isSiteLocalAddress(), "Public STUN address should not be a site-local (private) address.");
            logger.info("Public STUN address validation (loopback/site-local) passed.");
        } catch (Exception e) {
            fail("Failed to parse discovered public STUN address: " + e.getMessage());
        }
    }

    @Test
    void testInitiateConnection_NullAddress() {
        logger.info("Testing initiateConnection with null peer address...");
        p2pConnectionManager.initiateConnection(null);
        assertFalse(p2pConnectionManager.isConnected(), "Should not be connected with null peer address.");
        assertNull(p2pConnectionManager.getCurrentPeerAddress(), "Current peer address should be null.");
    }

    @Test
    void testInitiateConnection_EmptyAddress() {
        logger.info("Testing initiateConnection with empty peer address...");
        p2pConnectionManager.initiateConnection("   ");
        assertFalse(p2pConnectionManager.isConnected(), "Should not be connected with empty peer address.");
        assertNull(p2pConnectionManager.getCurrentPeerAddress(), "Current peer address should be null.");
    }


    @Test
    @Timeout(value = STUN_DISCOVERY_TIMEOUT_SECONDS, unit = TimeUnit.SECONDS)
    void testSendMessage_WhenConnected_Async() throws InterruptedException {
        logger.info("Testing sendMessage when connected (asynchronous)...");
        assumeTrue(isNetworkAvailable(), "Network connectivity is required for this test.");

        p2pConnectionManager.initiateConnection(TEST_PEER_ADDRESS);

        long startTime = System.currentTimeMillis();
        IceProcessingState finalIceState = null;

        while (System.currentTimeMillis() - startTime < TimeUnit.SECONDS.toMillis(STUN_DISCOVERY_TIMEOUT_SECONDS)) {
            if (p2pConnectionManager.getIceAgent() != null) finalIceState = p2pConnectionManager.getIceAgent().getState();

            if (p2pConnectionManager.isConnected()) {
                break;
            }
            if (p2pConnectionManager.getIceAgent() != null && IceProcessingState.FAILED.equals(finalIceState)) {
                logger.warn("ICE processing failed, sendMessage test will proceed assuming not connected.");
                break;
            }
            if (p2pConnectionManager.getIceAgent() == null || (IceProcessingState.TERMINATED.equals(finalIceState) && !p2pConnectionManager.isConnected())) {
                break;
            }
            Thread.sleep(POLLING_INTERVAL_MS);
        }

        if (p2pConnectionManager.getIceAgent() != null && finalIceState == null) finalIceState = p2pConnectionManager.getIceAgent().getState();

        if (p2pConnectionManager.isConnected()) {
            logger.info("ICE connection established (or STUN successful), proceeding to test sendMessage. Final ICE State: {}", finalIceState);
            // At this point, isConnected should be true if ICE completed successfully.
            // The actual message sending is simulated in P2PConnectionManager, so we just call it.
            // No exception should be thrown.
            assertDoesNotThrow(() -> p2pConnectionManager.sendMessage("Hello P2P World"), "sendMessage should not throw an exception when connected.");
        } else {
            logger.warn("sendMessage test: P2P connection not established. Final ICE State: {}. isConnected: {}", finalIceState, p2pConnectionManager.isConnected());
            // If not connected, sendMessage should ideally not throw an error but log a warning.
            // We can verify that it doesn't throw an exception.
            assertDoesNotThrow(() -> p2pConnectionManager.sendMessage("Hello P2P World (not connected)"), "sendMessage should not throw an exception even when not connected.");
        }
    }

    @Test
    @Timeout(value = STUN_DISCOVERY_TIMEOUT_SECONDS, unit = TimeUnit.SECONDS)
    void testReceiveMessage_WhenConnected_Async() throws InterruptedException {
        logger.info("Testing receiveMessage when connected (asynchronous)...");
        assumeTrue(isNetworkAvailable(), "Network connectivity is required for this test.");

        p2pConnectionManager.initiateConnection(TEST_PEER_ADDRESS);

        long startTime = System.currentTimeMillis();
        IceProcessingState finalIceState = null;

        while (System.currentTimeMillis() - startTime < TimeUnit.SECONDS.toMillis(STUN_DISCOVERY_TIMEOUT_SECONDS)) {
            if (p2pConnectionManager.getIceAgent() != null) finalIceState = p2pConnectionManager.getIceAgent().getState();

            if (p2pConnectionManager.isConnected()) {
                break;
            }
            if (p2pConnectionManager.getIceAgent() != null && IceProcessingState.FAILED.equals(finalIceState)) {
                logger.warn("ICE processing failed, receiveMessage test will proceed assuming not connected.");
                break;
            }
             if (p2pConnectionManager.getIceAgent() == null || (IceProcessingState.TERMINATED.equals(finalIceState) && !p2pConnectionManager.isConnected())) {
                break;
            }
            Thread.sleep(POLLING_INTERVAL_MS);
        }

        if (p2pConnectionManager.getIceAgent() != null && finalIceState == null) finalIceState = p2pConnectionManager.getIceAgent().getState();

        if (p2pConnectionManager.isConnected()) {
            logger.info("ICE connection established (or STUN successful), proceeding to test receiveMessage. Final ICE State: {}", finalIceState);
            // The actual message receiving is simulated.
            String message = p2pConnectionManager.receiveMessage();
            assertNotNull(message, "Received message should not be null when connected.");
            assertTrue(message.contains(TEST_PEER_ADDRESS), "Received message should contain peer address.");
        } else {
            logger.warn("receiveMessage test: P2P connection not established. Final ICE State: {}. isConnected: {}", finalIceState, p2pConnectionManager.isConnected());
            String message = p2pConnectionManager.receiveMessage();
            assertNull(message, "Received message should be null when not connected.");
        }
    }

    @Test
    @Timeout(value = STUN_DISCOVERY_TIMEOUT_SECONDS * 2, unit = TimeUnit.SECONDS) // Increased timeout for reconnect
    void testHandleReconnect_CallsInitiate_Async() throws InterruptedException {
        logger.info("Testing handleReconnect (asynchronous)...");
        assumeTrue(isNetworkAvailable(), "Network connectivity is required for reconnect test.");

        // Simulate a previous connection attempt that set lastPeerAddress
        String lastKnownPeer = "last.known.peer.address";
        p2pConnectionManager.setLastPeerAddressForTest(lastKnownPeer); // Using the test helper
        p2pConnectionManager.setCurrentPeerAddressForTest(null); // Ensure no current peer
        p2pConnectionManager.setIsConnectedForTest(false); // Ensure not connected

        p2pConnectionManager.handleReconnect(); // This should call initiateConnection with lastKnownPeer

        // Assert that initiateConnection was effectively called for lastKnownPeer
        // We check this by observing the ICE agent's state for completion or failure.
        long startTime = System.currentTimeMillis();
        boolean reconnectSuccessful = false;
        IceProcessingState finalIceState = null;

        while (System.currentTimeMillis() - startTime < TimeUnit.SECONDS.toMillis(STUN_DISCOVERY_TIMEOUT_SECONDS)) {
            if (p2pConnectionManager.getIceAgent() != null) finalIceState = p2pConnectionManager.getIceAgent().getState();

            if (p2pConnectionManager.isConnected() && p2pConnectionManager.getPublicStunAddress() != null &&
                lastKnownPeer.equals(p2pConnectionManager.getCurrentPeerAddress())) {
                reconnectSuccessful = true;
                break;
            }
            if (p2pConnectionManager.getIceAgent() != null && IceProcessingState.FAILED.equals(finalIceState)) {
                logger.warn("ICE processing failed during reconnect.");
                break;
            }
             if (p2pConnectionManager.getIceAgent() == null ||
                (IceProcessingState.TERMINATED.equals(finalIceState) && !p2pConnectionManager.isConnected())) {
                break;
            }
            Thread.sleep(POLLING_INTERVAL_MS);
        }

        if (p2pConnectionManager.getIceAgent() != null && finalIceState == null) finalIceState = p2pConnectionManager.getIceAgent().getState();

        assertTrue(reconnectSuccessful, "Reconnect attempt should result in connected state with public address and correct peer. Final ICE State: " + finalIceState + ", isConnected: " + p2pConnectionManager.isConnected() + ", publicAddress: " + p2pConnectionManager.getPublicStunAddress() + ", currentPeer: " + p2pConnectionManager.getCurrentPeerAddress());

        if (reconnectSuccessful) {
             assertEquals(lastKnownPeer, p2pConnectionManager.getCurrentPeerAddress(), "Current peer address should be the last known peer after reconnect.");
             logger.info("Reconnect successful to {}", lastKnownPeer);
        } else {
            logger.warn("Reconnect conditions not met. Final ICE State: {}, isConnected: {}, publicAddress: {}, currentPeer: {}",
                        finalIceState, p2pConnectionManager.isConnected(), p2pConnectionManager.getPublicStunAddress(), p2pConnectionManager.getCurrentPeerAddress());
        }
    }

    @Test
    void testCloseConnection() {
        logger.info("Testing closeConnection...");
        // Initiate a connection first (even if it doesn't fully complete, to set some state)
        p2pConnectionManager.initiateConnection(TEST_PEER_ADDRESS);
        // It's possible the ICE agent is still processing, but we can still call close.

        assertNotNull(p2pConnectionManager.getIceAgent(), "ICE Agent should exist before closeConnection.");
        p2pConnectionManager.closeConnection();

        assertNull(p2pConnectionManager.getIceAgent(), "ICE Agent should be null after closeConnection.");
        assertFalse(p2pConnectionManager.isConnected(), "Should not be connected after closeConnection.");
        assertNull(p2pConnectionManager.getCurrentPeerAddress(), "Current peer address should be null after closeConnection.");
        assertEquals(TEST_PEER_ADDRESS, p2pConnectionManager.getLastPeerAddressForTest(), "Last peer address should be set to the one before closing.");
        assertNull(p2pConnectionManager.getPublicStunAddress(), "Public STUN address should be null after closeConnection.");
        logger.info("closeConnection test completed.");
    }

    // Helper method to check network availability (basic check)
    private boolean isNetworkAvailable() {
        try {
            // Try to resolve a known hostname
            InetAddress.getByName("www.bing.com");
            logger.info("Network connectivity check: Succeeded (resolved bing.com).");
            return true;
        } catch (Exception e) {
            logger.warn("Network connectivity check: Failed (could not resolve bing.com). Test requiring network may be skipped or fail.", e);
            return false;
        }
    }
}
