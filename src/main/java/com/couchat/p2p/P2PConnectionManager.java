package com.couchat.p2p;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Agent;
import org.ice4j.ice.CandidatePair;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.IceProcessingState;
import org.ice4j.ice.harvest.CandidateHarvester;
import org.ice4j.ice.harvest.StunCandidateHarvester;
import org.ice4j.ice.harvest.TurnCandidateHarvester;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.net.BindException;
import java.util.List;

// TODO: Integrate with WireGuard for VPN tunnel establishment

/**
 * Manages P2P connections, including NAT traversal using STUN (via ice4j).
 */
public class P2PConnectionManager implements P2PConnectionInterface {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnectionManager.class);
    // Public STUN servers; more can be added or made configurable
    // private static final TransportAddress DEFAULT_STUN_SERVER_ADDRESS = new TransportAddress("stun.l.google.com", 19302, Transport.UDP);
    private static final TransportAddress DEFAULT_STUN_SERVER_ADDRESS = new TransportAddress("stun.hot-chilli.net", 3478, Transport.UDP);


    private String currentPeerAddress; // This would typically be a more complex identifier in a real system
    private String lastPeerAddress;
    private boolean isConnected;
    private TransportAddress publicAddress; // Stores the discovered public IP and port (from ice4j)
    private Agent iceAgent; // ice4j agent for managing ICE processing
    private static final String ICE_STREAM_NAME = "couchat-stream";
    private static final int BASE_PORT = 5000; // Base port for ICE agent, will try to bind here or higher
    private static final int MAX_PORT_RETRIES = 10;


    /**
     * Constructs a P2PConnectionManager and initializes the ICE agent.
     */
    public P2PConnectionManager() {
        this.isConnected = false;
        initializeIceAgent();
    }

    private void initializeIceAgent() {
        this.iceAgent = new Agent();
        iceAgent.setControlling(true); // Or determine dynamically based on who initiates

        // Add a STUN harvester
        StunCandidateHarvester stunHarvester = new StunCandidateHarvester(DEFAULT_STUN_SERVER_ADDRESS);
        iceAgent.addCandidateHarvester(stunHarvester);

        // Create a media stream
        IceMediaStream stream = null;
        try {
            // API CHANGE: createMediaStream(String name) is expected.
            // Port binding is typically handled by components within the stream or agent's transport manager.
            // The retry loop for BindException on stream creation is removed as it's less applicable here.
            stream = iceAgent.createMediaStream(ICE_STREAM_NAME);
            logger.info("ICE Agent created media stream '{}'. Port binding for components will occur during candidate harvesting.", ICE_STREAM_NAME);
        } catch (Exception e) {
            logger.error("Failed to create ICE media stream '{}': {}. Aborting P2PConnectionManager initialization.", ICE_STREAM_NAME, e.getMessage(), e);
            // Throw a runtime exception to indicate that the P2PConnectionManager could not be initialized properly.
            throw new RuntimeException("Failed to initialize ICE Agent: Could not create media stream " + ICE_STREAM_NAME, e);
        }

        // Add a listener for ICE processing state changes
        iceAgent.addStateChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (Agent.PROPERTY_ICE_PROCESSING_STATE.equals(evt.getPropertyName())) {
                    IceProcessingState newState = (IceProcessingState) evt.getNewValue();
                    logger.info("ICE Agent state changed to: {}", newState);

                    if (newState == IceProcessingState.COMPLETED) {
                        logger.info("ICE Agent state changed to: COMPLETED.");
                        boolean srflxFound = false;
                        TransportAddress discoveredPublicAddress = null;

                        if (iceAgent != null) {
                            IceMediaStream stream = iceAgent.getStream(ICE_STREAM_NAME);
                            if (stream != null) {
                                Component component = stream.getComponent(Component.RTP);
                                if (component != null) {
                                    logger.info("Local candidates on COMPLETED for component {}:", component.getComponentID());
                                    component.getLocalCandidates().forEach(c -> logger.info("  LCL_CAND (COMPLETED): {}, Type: {}", c, c.getType()));

                                    // Prioritize finding a server reflexive candidate directly from local candidates
                                    for (org.ice4j.ice.Candidate<?> candidate : component.getLocalCandidates()) {
                                        if (candidate.getType().equals(org.ice4j.ice.CandidateType.SERVER_REFLEXIVE_CANDIDATE)) {
                                            discoveredPublicAddress = candidate.getTransportAddress();
                                            logger.info("Discovered public STUN address (Server Reflexive) on COMPLETED: {}:{}",
                                                    discoveredPublicAddress.getHostAddress(), discoveredPublicAddress.getPort());
                                            srflxFound = true;
                                            break;
                                        }
                                    }

                                    CandidatePair selectedPair = component.getSelectedPair();
                                    if (selectedPair != null) {
                                        logger.info("A candidate pair was selected: {}", selectedPair);
                                        if (!srflxFound && selectedPair.getLocalCandidate() != null) {
                                            // Fallback if SRFLX not found directly but a pair exists
                                            TransportAddress localCandidateAddress = selectedPair.getLocalCandidate().getTransportAddress();
                                            logger.warn("Using selected local candidate address as publicAddress on COMPLETED (SRFLX not found directly): {}. This might be a host or other type of candidate.", localCandidateAddress);
                                            // If discoveredPublicAddress is still null, consider this one.
                                            // Check if this candidate is server-reflexive.
                                            if (selectedPair.getLocalCandidate().getType().equals(org.ice4j.ice.CandidateType.SERVER_REFLEXIVE_CANDIDATE)) {
                                                if(discoveredPublicAddress == null) discoveredPublicAddress = localCandidateAddress;
                                                srflxFound = true;
                                            } else if (discoveredPublicAddress == null) {
                                                // Only use if nothing better was found, and be cautious.
                                                // discoveredPublicAddress = localCandidateAddress;
                                                logger.warn("Selected local candidate is not server-reflexive. Public IP might not be correctly identified.");
                                            }
                                        }
                                        // If a pair is selected, actual P2P connection is considered possible
                                        P2PConnectionManager.this.isConnected = true;
                                        logger.info("P2P connection (ICE) established with a selected pair. isConnected=true.");
                                    } else {
                                        logger.warn("ICE processing completed, but no candidate pair was selected for stream '{}'.", ICE_STREAM_NAME);
                                        // If SRFLX was found, still consider STUN discovery successful for connectivity
                                        if (srflxFound) {
                                            P2PConnectionManager.this.isConnected = true;
                                            logger.info("STUN discovery successful (public address found via SRFLX), even if no pair selected. isConnected=true.");
                                        } else {
                                            P2PConnectionManager.this.isConnected = false;
                                            logger.warn("No SRFLX candidate found and no pair selected on COMPLETED. isConnected=false.");
                                        }
                                    }

                                    if(discoveredPublicAddress != null) {
                                        P2PConnectionManager.this.publicAddress = discoveredPublicAddress;
                                    }

                                } else { P2PConnectionManager.this.isConnected = false; logger.warn("Stream component is null on COMPLETED."); }
                            } else { P2PConnectionManager.this.isConnected = false; logger.warn("ICE media stream is null on COMPLETED.");}
                        } else { P2PConnectionManager.this.isConnected = false; logger.warn("ICE Agent was null on COMPLETED state change."); }

                        // Final consolidation: if a public address was found, isConnected should reflect that for STUN purposes.
                        if (P2PConnectionManager.this.publicAddress != null && !P2PConnectionManager.this.isConnected) {
                            logger.info("Public address was found, ensuring isConnected is true for STUN success on COMPLETED.");
                            P2PConnectionManager.this.isConnected = true;
                        }
                         if (P2PConnectionManager.this.publicAddress == null && P2PConnectionManager.this.isConnected){
                            logger.warn("isConnected is true, but publicAddress is null on COMPLETED. This might be an issue.");
                            // Potentially set isConnected to false if public address is critical and not found.
                            // For now, this indicates a potential logic flaw or unexpected ICE behavior.
                        }

                    } else if (newState == IceProcessingState.FAILED) {
                        logger.error("ICE Agent processing failed. P2P connection cannot be established.");
                        P2PConnectionManager.this.isConnected = false;
                    } else if (newState == IceProcessingState.TERMINATED) {
                        logger.info("ICE Agent state changed to: TERMINATED.");
                        // If COMPLETED was not reached or did not successfully set publicAddress/isConnected,
                        // and we haven't already found a public address,
                        // try to find a server reflexive candidate now as a last resort.
                        if (P2PConnectionManager.this.publicAddress == null && iceAgent != null) {
                            IceMediaStream stream = iceAgent.getStream(ICE_STREAM_NAME);
                            if (stream != null) {
                                Component component = stream.getComponent(Component.RTP);
                                if (component != null) {
                                    logger.info("Local candidates on TERMINATED for component {}:", component.getComponentID());
                                    component.getLocalCandidates().forEach(c -> logger.info("  LCL_CAND (TERMINATED): {}, Type: {}", c, c.getType()));

                                    for (org.ice4j.ice.Candidate<?> candidate : component.getLocalCandidates()) {
                                        if (candidate.getType().equals(org.ice4j.ice.CandidateType.SERVER_REFLEXIVE_CANDIDATE)) {
                                            P2PConnectionManager.this.publicAddress = candidate.getTransportAddress();
                                            logger.info("Discovered public STUN address (Server Reflexive) on TERMINATED: {}:{}",
                                                    P2PConnectionManager.this.publicAddress.getHostAddress(), P2PConnectionManager.this.publicAddress.getPort());
                                            P2PConnectionManager.this.isConnected = true; // STUN discovery successful
                                            break;
                                        }
                                    }
                                    if (P2PConnectionManager.this.publicAddress == null) {
                                        logger.warn("No SERVER_REFLEXIVE_CANDIDATE found on TERMINATED state after checking local candidates.");
                                    }
                                }
                            }
                        }
                        // Final check on TERMINATED
                        if (!P2PConnectionManager.this.isConnected && P2PConnectionManager.this.publicAddress != null) {
                             logger.info("Public address was found, ensuring isConnected is true for STUN success on TERMINATED.");
                             P2PConnectionManager.this.isConnected = true;
                        }
                        if (!P2PConnectionManager.this.isConnected) {
                             logger.warn("ICE Terminated. isConnected is false. Public STUN address {} found.", (P2PConnectionManager.this.publicAddress != null ? "was" : "was NOT"));
                        }
                    }
                }
            }
        });
    }


    /**
     * Initiates a P2P connection with the specified peer address.
     * This involves starting the ICE process to discover local and public addresses
     * and to attempt to establish a connection with the peer.
     *
     * @param peerAddress The address of the peer to connect to. (Note: ice4j handles peer address as remote candidates)
     */
    @Override
    public void initiateConnection(String peerAddress) {
        logger.info("Attempting to initiate P2P connection with peer: {}", peerAddress);

        if (peerAddress == null || peerAddress.trim().isEmpty()) {
            logger.warn("Cannot initiate connection: peer address is null or empty.");
            this.isConnected = false;
            return;
        }
        // this.currentPeerAddress = peerAddress; // Set after successful stubbing or ICE

        if (this.iceAgent == null) {
            logger.error("ICE Agent is not initialized. Cannot start connection process.");
            this.isConnected = false;
            return;
        }

        // PROTOTYPE STUB: Simulate successful P2P connection for LAN environment
        logger.warn("PROTOTYPE STUB: Simulating successful P2P connection for peer: {}. Bypassing actual ICE process.", peerAddress);
        this.currentPeerAddress = peerAddress;
        this.isConnected = true;
        this.publicAddress = new TransportAddress("127.0.0.1", 12345, Transport.UDP);
        logger.info("PROTOTYPE STUB: Set isConnected=true, publicAddress={}", this.publicAddress);
        // IMPORTANT: Return here to bypass actual ICE processing for the stub
        return;

/*
        // Original ICE processing code - effectively bypassed by the return above
        try {
            IceMediaStream stream = iceAgent.getStream(ICE_STREAM_NAME);
            if (stream == null) {
                 logger.error("ICE media stream '{}' not found. Cannot initiate connection.", ICE_STREAM_NAME);
                 this.isConnected = false;
                 return;
            }
            iceAgent.startConnectivityEstablishment();

            logger.info("ICE candidate gathering and connectivity checks should be in progress (or will start). Public address will be updated on completion.");
        } catch (Exception e) {
            logger.error("Exception during P2P connection initiation with peer {}: {}", peerAddress, e.getMessage(), e);
            this.isConnected = false;
        }
*/
    }

    /**
     * Handles reconnection attempts.
     * It tries to reconnect to the current peer if available, otherwise to the last known peer.
     */
    @Override
    public void handleReconnect() {
        if (this.currentPeerAddress != null && !this.currentPeerAddress.isEmpty()) {
            logger.info("Attempting to reconnect to current peer: {}", this.currentPeerAddress);
            initiateConnection(this.currentPeerAddress);
        } else if (this.lastPeerAddress != null && !this.lastPeerAddress.isEmpty()) {
            logger.info("Attempting to reconnect to last peer: {}", this.lastPeerAddress);
            initiateConnection(this.lastPeerAddress);
        } else {
            logger.warn("No previous peer address available to reconnect.");
            this.isConnected = false;
        }
    }

    /**
     * Sends a message to the currently connected peer.
     * (Placeholder - actual data sending needs implementation via established ICE connection)
     *
     * @param message The message to send.
     */
    @Override
    public void sendMessage(String message) {
        if (!this.isConnected || this.currentPeerAddress == null) {
            logger.warn("Cannot send message, no active P2P connection or peer address is null. (ICE State: {})", iceAgent != null ? iceAgent.getState() : "Agent Null");
            return;
        }
        if (message == null || message.isEmpty()) {
            logger.warn("Cannot send an empty message.");
            return;
        }
        // Actual sending would use the selected CandidatePair's DatagramSocket or equivalent
        logger.info("Simulating sending message to {} (via ICE): {}", this.currentPeerAddress, message);
    }

    /**
     * Receives a message from the currently connected peer.
     * (Placeholder - actual data receiving needs implementation via established ICE connection)
     *
     * @return A simulated received message, or null if not connected.
     */
    @Override
    public String receiveMessage() {
        if (!this.isConnected || this.currentPeerAddress == null) {
            logger.warn("Cannot receive message, no active P2P connection or peer address is null. (ICE State: {})", iceAgent != null ? iceAgent.getState() : "Agent Null");
            return null;
        }
        // Actual receiving would use the selected CandidatePair's DatagramSocket or equivalent
        String receivedMessage = "Simulated received message from " + this.currentPeerAddress + " (via ICE)";
        logger.info("Received message: {}", receivedMessage);
        return receivedMessage;
    }

    /**
     * Closes the current P2P connection by freeing ICE agent resources.
     */
    public void closeConnection() {
        if (this.iceAgent != null) {
            logger.info("Closing P2P connection (freeing ICE agent resources) with: {}", this.currentPeerAddress);
            try {
                this.iceAgent.free(); // Release resources used by the agent
            } catch (Exception e) {
                logger.error("Error while freeing ICE agent resources: {}", e.getMessage(), e);
            }
            this.iceAgent = null; // Nullify to allow re-initialization if needed
        }
        this.lastPeerAddress = this.currentPeerAddress;
        this.currentPeerAddress = null;
        this.isConnected = false;
        this.publicAddress = null;
        logger.info("P2P connection closed.");
    }

    /**
     * Checks if a P2P connection is currently considered active.
     * This is based on the ICE processing state.
     *
     * @return true if connected, false otherwise.
     */
    public boolean isConnected() {
        // isConnected is updated by the ICE state listener.
        return isConnected;
    }

    /**
     * Gets the address of the peer this manager is trying to connect to or is connected to.
     *
     * @return The current peer address, or null if not set.
     */
    public String getCurrentPeerAddress() {
        return currentPeerAddress;
    }

    /**
     * Gets the discovered public (server reflexive) address.
     *
     * @return The {@link TransportAddress} representing the public IP and port,
     *         or null if not discovered or ICE processing not completed.
     */
    public TransportAddress getPublicStunAddress() {
        return publicAddress;
    }

    /**
     * Gets the underlying ICE Agent.
     * Useful for more advanced control or inspection.
     * @return The {@link Agent} instance.
     */
    public Agent getIceAgent() {
        return iceAgent;
    }

    /**
     * Gets the last peer address for testing purposes.
     * This method should only be used in test environments.
     *
     * @return The last peer address.
     */
    String getLastPeerAddressForTest() {
        logger.warn("Calling test-only method getLastPeerAddressForTest.");
        return this.lastPeerAddress;
    }

    /**
     * Sets the last peer address for testing purposes.
     * This method should only be used in test environments.
     *
     * @param address The address to set as the last peer address.
     */
    void setLastPeerAddressForTest(String address) {
        logger.warn("Calling test-only method setLastPeerAddressForTest with address: {}", address);
        this.lastPeerAddress = address;
    }

    /**
     * Sets the current peer address for testing purposes.
     * @param currentPeerAddress The address to set.
     */
    void setCurrentPeerAddressForTest(String currentPeerAddress) {
        this.currentPeerAddress = currentPeerAddress;
    }

    /**
     * Sets the connection status for testing purposes.
     * @param isConnected The connection status to set.
     */
    void setIsConnectedForTest(boolean isConnected) {
        this.isConnected = isConnected;
    }
}
