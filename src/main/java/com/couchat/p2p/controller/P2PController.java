package com.couchat.p2p.controller;

import com.couchat.p2p.DeviceDiscoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/api/p2p")
public class P2PController {

    private static final Logger logger = LoggerFactory.getLogger(P2PController.class);
    private final DeviceDiscoveryService deviceDiscoveryService;
    private final com.couchat.p2p.P2PConnectionManager p2pConnectionManager;

    @Autowired
    public P2PController(DeviceDiscoveryService deviceDiscoveryService, com.couchat.p2p.P2PConnectionManager p2pConnectionManager) {
        this.deviceDiscoveryService = deviceDiscoveryService;
        this.p2pConnectionManager = p2pConnectionManager;
    }

    @GetMapping("/discovered-peers")
    public ResponseEntity<Set<DeviceDiscoveryService.DiscoveredPeer>> getDiscoveredPeers() {
        logger.info("GET /api/p2p/discovered-peers - Request received");
        Set<DeviceDiscoveryService.DiscoveredPeer> peers = deviceDiscoveryService.getDiscoveredPeers();
        logger.info("Returning {} discovered peers", peers.size());
        return ResponseEntity.ok(peers);
    }

    @PostMapping("/connect/{peerId}")
    public ResponseEntity<String> connectToPeer(@PathVariable String peerId) {
        logger.info("POST /api/p2p/connect/{} - Request received", peerId);
        if (peerId == null || peerId.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Peer ID cannot be empty.");
        }
        try {
            boolean success = p2pConnectionManager.connectToPeer(peerId);
            if (success) {
                return ResponseEntity.ok("Successfully initiated connection to peer: " + peerId);
            } else {
                return ResponseEntity.status(404).body("Peer not found or connection failed: " + peerId);
            }
        } catch (IllegalStateException e) {
            logger.warn("Connection attempt to {} failed: {}", peerId, e.getMessage());
            return ResponseEntity.status(409).body(e.getMessage());
        } catch (Exception e) {
            logger.error("Error connecting to peer {}: {}", peerId, e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Error connecting to peer: " + peerId);
        }
    }
}
