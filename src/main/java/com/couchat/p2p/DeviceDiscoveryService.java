package com.couchat.p2p;

import com.couchat.auth.PasskeyAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Service for discovering other CouChat devices on the local network using multicast.
 * It broadcasts this device's presence and listens for broadcasts from other peers
 * on all suitable network interfaces.
 * Relies on {@link PasskeyAuthService} to obtain the local peer ID.
 */
@Service
public class DeviceDiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DeviceDiscoveryService.class);
    private static final String MULTICAST_ADDRESS = "230.0.0.1";
    private static final int DISCOVERY_PORT = 8888;
    private static final int BROADCAST_INTERVAL_MS = 5000;
    private static final int PEER_TIMEOUT_MS = 15000;
    private static final int MULTICAST_TTL = 1; // TTL for LAN-only

    private final PasskeyAuthService passkeyAuthService;

    private InetAddress group;
    private final ScheduledExecutorService scheduler;
    private final ConcurrentHashMap<String, DiscoveredPeer> discoveredPeers = new ConcurrentHashMap<>();
    private String localPeerId;
    private int localServicePort = -1;
    private volatile boolean isDiscoveryStarted = false;

    // Store sockets and their associated interface information
    private final Map<NetworkInterface, MulticastSocket> interfaceToSocketMap = new ConcurrentHashMap<>();
    private final Map<NetworkInterface, String> activeInterfaceToIpMap = new ConcurrentHashMap<>();
    private final List<Thread> listenerThreads = new ArrayList<>();


    @Autowired
    public DeviceDiscoveryService(PasskeyAuthService passkeyAuthService) {
        this.passkeyAuthService = passkeyAuthService;
        // Scheduler for broadcast and cleanup tasks. Listener threads will be managed separately.
        this.scheduler = Executors.newScheduledThreadPool(2);
    }

    @PostConstruct
    public void init() {
        logger.info("DeviceDiscoveryService initialized. Waiting for authentication to start discovery.");
        // Initial identification of interfaces. This might be re-evaluated if startDiscovery is called later.
        identifyAllSuitableInterfaces();
    }

    private void identifyAllSuitableInterfaces() {
        this.activeInterfaceToIpMap.clear();
        int interfacesEvaluated = 0;
        int suitableInterfacesFound = 0;

        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface ni = networkInterfaces.nextElement();
                interfacesEvaluated++;
                String interfaceName = ni.getName();
                String interfaceDisplayName = ni.getDisplayName();
                logger.info("[InterfaceEval] Evaluating interface: Name: '{}', DisplayName: '{}', isVirtual: {}, MTU: {}",
                            interfaceName, interfaceDisplayName, ni.isVirtual(), getMTUSafe(ni)); // Added safe MTU logging

                if (ni.isLoopback()) {
                    logger.info("[InterfaceEval] Skipping '{}': Is loopback.", interfaceDisplayName);
                    continue;
                }
                if (!ni.isUp()) {
                    logger.info("[InterfaceEval] Skipping '{}': Is not up.", interfaceDisplayName);
                    continue;
                }
                if (!ni.supportsMulticast()) {
                    logger.info("[InterfaceEval] Skipping '{}': Does not support multicast.", interfaceDisplayName);
                    continue;
                }

                // Restore basic keyword filtering for known problematic virtual interfaces
                String displayNameLower = interfaceDisplayName.toLowerCase();
                // Keywords for interfaces that are almost certainly not the primary LAN/WLAN
                String[] definitelyBadKeywords = {"virtualbox host-only", "vmnet", "bluetooth", "microsoft wi-fi direct", "loopback", "teredo", "isatap", "6to4", "ppp", "tap"}; // Added ppp, tap
                boolean isDefinitelyBad = false;
                for (String keyword : definitelyBadKeywords) {
                    if (displayNameLower.contains(keyword)) {
                        logger.info("[InterfaceEval] Skipping '{}' due to definitely bad keyword: '{}'", interfaceDisplayName, keyword);
                        isDefinitelyBad = true;
                        break;
                    }
                }
                if (isDefinitelyBad) {
                    continue;
                }


                Enumeration<InetAddress> inetAddresses = ni.getInetAddresses();
                String suitableIpForThisInterface = null;
                boolean foundIPv4 = false;
                boolean currentCandidateIsLinkLocal = false; // Track if the current suitableIpForThisInterface is link-local

                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = inetAddresses.nextElement();
                    boolean isIPv4 = inetAddress.getHostAddress().indexOf(':') == -1;
                    logger.info("[InterfaceEval]   IP for '{}': {}, isSiteLocal: {}, isLinkLocal: {}, isLoopback: {}, isIPv4: {}",
                                interfaceDisplayName, inetAddress.getHostAddress(), inetAddress.isSiteLocalAddress(),
                                inetAddress.isLinkLocalAddress(), inetAddress.isLoopbackAddress(), isIPv4);

                    if (isIPv4 && !inetAddress.isLoopbackAddress()) {
                        if (inetAddress.isSiteLocalAddress()) {
                            suitableIpForThisInterface = inetAddress.getHostAddress();
                            currentCandidateIsLinkLocal = false;
                            logger.info("[InterfaceEval]   Selected site-local IPv4 {} for interface '{}'", suitableIpForThisInterface, interfaceDisplayName);
                            foundIPv4 = true;
                            break; // Prefer site-local if available
                        } else if (inetAddress.isLinkLocalAddress()) {
                            if (suitableIpForThisInterface == null) { // Only take link-local if no other candidate yet
                                suitableIpForThisInterface = inetAddress.getHostAddress();
                                currentCandidateIsLinkLocal = true;
                                logger.info("[InterfaceEval]   Candidate link-local IPv4 {} for interface '{}'", suitableIpForThisInterface, interfaceDisplayName);
                                foundIPv4 = true;
                            }
                        } else { // Non-site-local, non-link-local (e.g., public IP)
                            if (suitableIpForThisInterface == null || currentCandidateIsLinkLocal) {
                                // If no candidate yet, or current candidate is link-local, prefer this one.
                                suitableIpForThisInterface = inetAddress.getHostAddress();
                                currentCandidateIsLinkLocal = false;
                                logger.info("[InterfaceEval]   Candidate non-loopback/non-site-local IPv4 {} for interface '{}' (overwriting previous if it was null or link-local)", suitableIpForThisInterface, interfaceDisplayName);
                                foundIPv4 = true;
                            }
                        }
                    }
                }

                if (foundIPv4 && suitableIpForThisInterface != null) {
                    if (ni.isVirtual()) {
                         logger.warn("[InterfaceEval] SUCCESS (Virtual Interface): Identified suitable IP {} for VIRTUAL interface: {} ({}). This might not be the desired LAN interface.",
                                     suitableIpForThisInterface, interfaceName, interfaceDisplayName);
                    } else {
                        logger.info("[InterfaceEval] SUCCESS (Physical Interface): Identified suitable IP {} for PHYSICAL interface: {} ({})",
                                     suitableIpForThisInterface, interfaceName, interfaceDisplayName);
                    }
                    this.activeInterfaceToIpMap.put(ni, suitableIpForThisInterface);
                    suitableInterfacesFound++;
                } else {
                    logger.info("[InterfaceEval] SKIPPED '{}': Did not find a suitable non-loopback IPv4 address.", interfaceDisplayName);
                }
            }
        } catch (SocketException e) {
            logger.error("SocketException while enumerating network interfaces for discovery", e);
        }
        logger.info("Interface identification complete. Evaluated: {}, Suitable found: {}.", interfacesEvaluated, suitableInterfacesFound);

        if (this.activeInterfaceToIpMap.isEmpty()) {
            logger.warn("No suitable network interfaces found for device discovery. Discovery may not function correctly.");
        }
    }


    public synchronized void startDiscovery() {
        if (isDiscoveryStarted) {
            logger.info("Device discovery already started.");
            return;
        }

        if (!passkeyAuthService.isAuthenticated() || passkeyAuthService.getLocalUserId() == null) {
            logger.warn("Attempted to start discovery, but user is not authenticated or local user ID is null.");
            return;
        }

        this.localPeerId = passkeyAuthService.getLocalUserId();
        if (this.localPeerId == null || this.localPeerId.isEmpty()) {
             logger.error("Cannot start discovery: Local User ID is still not available.");
             return;
        }
        if (this.localServicePort <= 0) {
            logger.error("Cannot start discovery: Local service port ({}) is not set or invalid.", this.localServicePort);
            return;
        }

        // Re-identify interfaces in case network conditions changed
        identifyAllSuitableInterfaces();
        if (this.activeInterfaceToIpMap.isEmpty()) {
            logger.error("Cannot start discovery: No suitable network interfaces identified after re-evaluation.");
            return;
        }

        logger.info("Starting Device Discovery for Peer ID: {} on service port: {}. Identified interfaces:",
            this.localPeerId, this.localServicePort);
        for (Map.Entry<NetworkInterface, String> entry : activeInterfaceToIpMap.entrySet()) {
            logger.info("  - Interface: {} ({}), IP for broadcast: {}", entry.getKey().getName(), entry.getKey().getDisplayName(), entry.getValue());
        }

        try {
            this.group = InetAddress.getByName(MULTICAST_ADDRESS);
            // Clear previous sockets and threads if any (e.g., from a failed start or restart)
            stopListenerThreadsAndCloseSockets(); // Ensure clean state

            for (Map.Entry<NetworkInterface, String> entry : activeInterfaceToIpMap.entrySet()) {
                NetworkInterface ni = entry.getKey();
                try {
                    MulticastSocket ms = new MulticastSocket(DISCOVERY_PORT);
                    ms.setReuseAddress(true);
                    ms.setOption(StandardSocketOptions.IP_MULTICAST_IF, ni);
                    ms.setOption(StandardSocketOptions.IP_MULTICAST_TTL, MULTICAST_TTL);
                    ms.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, false); // false = disable loopback

                    SocketAddress multicastGroupAddress = new java.net.InetSocketAddress(this.group, DISCOVERY_PORT);
                    ms.joinGroup(multicastGroupAddress, ni);

                    this.interfaceToSocketMap.put(ni, ms);
                    logger.info("Successfully set up multicast socket on interface: {} ({}) and joined group {}. Loopback: false.",
                                ni.getName(), ni.getDisplayName(), MULTICAST_ADDRESS);

                    Thread listenerThread = new Thread(() -> listenOnSocket(ms, ni), "DiscoveryListener-" + ni.getName().replace(" ", "_"));
                    listenerThread.setDaemon(true);
                    listenerThreads.add(listenerThread);
                    // Listener threads will be started after all sockets are configured, just before setting isDiscoveryStarted = true

                } catch (IOException | UnsupportedOperationException e) {
                    logger.error("Failed to set up multicast socket or join group for interface {} ({}): {}",
                                 ni.getName(), ni.getDisplayName(), e.getMessage(), e);
                    // Clean up this specific socket if it was partially created
                    MulticastSocket failedSocket = this.interfaceToSocketMap.remove(ni);
                    if (failedSocket != null && !failedSocket.isClosed()) {
                        failedSocket.close();
                    }
                }
            }

            if (this.interfaceToSocketMap.isEmpty()) {
                logger.error("No multicast sockets could be successfully initialized. Discovery will not function.");
                // isDiscoveryStarted remains false
                return;
            }

            isDiscoveryStarted = true; // Set flag before starting threads and scheduled tasks
            logger.info("DeviceDiscoveryService discovery marked as started. Starting {} listener threads.", listenerThreads.size());

            for(Thread t : listenerThreads) {
                t.start();
            }

            scheduler.scheduleAtFixedRate(this::broadcastPresence, 0, BROADCAST_INTERVAL_MS, TimeUnit.MILLISECONDS);
            scheduler.scheduleAtFixedRate(this::cleanupInactivePeers, PEER_TIMEOUT_MS, PEER_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            logger.info("DeviceDiscoveryService broadcast and cleanup tasks scheduled.");

        } catch (IOException e) { // For InetAddress.getByName()
            logger.error("IOException during P2P discovery service startup (getting multicast group): {}", e.getMessage(), e);
            isDiscoveryStarted = false;
            stopListenerThreadsAndCloseSockets(); // Cleanup
            // Shutdown scheduler if it was started for other things or if tasks were scheduled
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdownNow();
            }
        }
    }

    private synchronized void stopListenerThreadsAndCloseSockets() {
        logger.debug("Stopping listener threads and closing multicast sockets...");
        for (Thread listenerThread : listenerThreads) {
            if (listenerThread.isAlive()) {
                listenerThread.interrupt();
            }
        }
        for (Thread listenerThread : listenerThreads) {
            try {
                if (listenerThread.isAlive()) {
                    listenerThread.join(1000); // Wait for up to 1 second
                    if (listenerThread.isAlive()) {
                        logger.warn("Listener thread {} did not terminate gracefully.", listenerThread.getName());
                    }
                }
            } catch (InterruptedException e) {
                logger.warn("Interrupted while waiting for listener thread {} to join.", listenerThread.getName());
                Thread.currentThread().interrupt();
            }
        }
        listenerThreads.clear();

        for (Map.Entry<NetworkInterface, MulticastSocket> entry : interfaceToSocketMap.entrySet()) {
            MulticastSocket ms = entry.getValue();
            NetworkInterface ni = entry.getKey();
            if (ms != null && !ms.isClosed()) {
                try {
                    if (this.group != null) {
                        SocketAddress multicastGroupAddressToLeave = new java.net.InetSocketAddress(this.group, DISCOVERY_PORT);
                        ms.leaveGroup(multicastGroupAddressToLeave, ni);
                        // logger.trace("Left multicast group on interface: {}", ni.getDisplayName());
                    }
                } catch (IOException e) {
                    logger.warn("Error leaving multicast group on interface {}: {}", ni.getDisplayName(), e.getMessage());
                } finally {
                    ms.close();
                    // logger.trace("Multicast socket closed for interface: {}", ni.getDisplayName());
                }
            }
        }
        interfaceToSocketMap.clear();
        logger.debug("All listener threads stopped and multicast sockets closed.");
    }

    // This method is called by Spring's PreDestroy or a custom shutdown hook
    public synchronized void stopDiscovery() {
        logger.info("stopDiscovery() called. Current discovery state: {}", isDiscoveryStarted);
        if (!isDiscoveryStarted && listenerThreads.isEmpty() && interfaceToSocketMap.isEmpty()) {
            logger.info("Discovery not active or already fully stopped.");
             // Ensure scheduler is shutdown if it was initialized
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(1, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }
            return;
        }
        logger.info("Stopping device discovery...");
        isDiscoveryStarted = false; // Signal all loops to stop

        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                    if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        logger.error("Scheduler did not terminate.");
                    }
                }
            } catch (InterruptedException ie) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            logger.info("Discovery scheduler shutdown.");
        }

        stopListenerThreadsAndCloseSockets();

        discoveredPeers.clear();
        logger.info("Device discovery stopped and resources released.");
    }

    private void broadcastPresence() {
        if (!isDiscoveryStarted || localPeerId == null || localPeerId.isEmpty() || activeInterfaceToIpMap.isEmpty()) {
            return;
        }
        if (localServicePort <= 0) {
            logger.warn("Cannot broadcast presence: Local service port is not set or invalid ({}).", localServicePort);
            return;
        }

        int successfulBroadcasts = 0;
        for (Map.Entry<NetworkInterface, MulticastSocket> socketEntry : interfaceToSocketMap.entrySet()) {
            NetworkInterface ni = socketEntry.getKey();
            MulticastSocket ms = socketEntry.getValue();
            String ipForBroadcast = activeInterfaceToIpMap.get(ni);

            if (ipForBroadcast == null) {
                logger.warn("No IP address found for interface {} (used by socket {}) during broadcast. Skipping.", ni.getDisplayName(), ms.getLocalSocketAddress());
                continue;
            }

            try {
                String message = String.format("%s:%s:%d", localPeerId, ipForBroadcast, localServicePort);
                byte[] buffer = message.getBytes(StandardCharsets.UTF_8);
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, this.group, DISCOVERY_PORT);

                if (ms != null && !ms.isClosed()) {
                    ms.send(packet);
                    logger.debug("Broadcasted presence via interface {}({}): {}", ni.getDisplayName(), ipForBroadcast, message);
                    successfulBroadcasts++;
                } else {
                    logger.warn("Cannot broadcast presence on interface {}: Multicast socket is null or closed.", ni.getDisplayName());
                }
            } catch (IOException e) {
                logger.warn("IOException during broadcastPresence on interface {}: {}", ni.getDisplayName(), e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error during broadcastPresence on interface {}", ni.getDisplayName(), e);
            }
        }
        if (successfulBroadcasts == 0 && !interfaceToSocketMap.isEmpty()) { // Check interfaceToSocketMap as activeInterfaceToIpMap might have entries for which sockets failed
            logger.warn("Failed to broadcast presence on any interface where a socket was active.");
        }
    }

    private void listenOnSocket(MulticastSocket socket, NetworkInterface interfaceContext) {
        logger.info("Listener started for interface {} ({}) on socket: {}", interfaceContext.getName(), interfaceContext.getDisplayName(), socket.getLocalSocketAddress());
        byte[] buffer = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        while (isDiscoveryStarted && !Thread.currentThread().isInterrupted() && socket != null && !socket.isClosed()) {
            try {
                socket.receive(packet);
                String receivedMessage = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
                logger.debug("Interface {}: Received discovery packet from {}:{} - {}", interfaceContext.getDisplayName(), packet.getAddress().getHostAddress(), packet.getPort(), receivedMessage);

                String[] parts = receivedMessage.split(":");
                if (parts.length == 3) {
                    String peerId = parts[0];
                    String peerIpAdvertised = parts[1];
                    int peerServicePort = Integer.parseInt(parts[2]);

                    boolean isSelf = peerId.equals(localPeerId);
                    // Further check if the advertised IP and port match any of our own,
                    // though IP_MULTICAST_LOOP=false should prevent receiving on the sending socket.
                    // This helps if the packet is received on a *different* local interface.
                    if (!isSelf) {
                        for (String selfIp : activeInterfaceToIpMap.values()) {
                            if (peerIpAdvertised.equals(selfIp) && peerServicePort == this.localServicePort) {
                                isSelf = true;
                                logger.trace("Ignored self-broadcast received on interface {} (from advertised IP {} matching one of our own).", interfaceContext.getDisplayName(), peerIpAdvertised);
                                break;
                            }
                        }
                    }

                    if (isSelf) {
                        continue;
                    }

                    DiscoveredPeer discoveredPeer = new DiscoveredPeer(peerId, peerIpAdvertised, peerServicePort, System.currentTimeMillis());
                    DiscoveredPeer previous = discoveredPeers.put(peerId, discoveredPeer);
                    if (previous == null || !previous.getIpAddress().equals(peerIpAdvertised) || previous.getServicePort() != peerServicePort) {
                         logger.info("Interface {}: Discovered or updated peer: {}", interfaceContext.getDisplayName(), discoveredPeer);
                    } else {
                         logger.trace("Interface {}: Refreshed peer: {}", interfaceContext.getDisplayName(), discoveredPeer);
                    }

                } else {
                    logger.warn("Interface {}: Received malformed discovery packet: {}", interfaceContext.getDisplayName(), receivedMessage);
                }
            } catch (SocketException se) {
                if (socket.isClosed() || !isDiscoveryStarted) {
                    logger.info("Listener for interface {}: Socket closed or discovery stopped, terminating listener.", interfaceContext.getDisplayName());
                    break;
                }
                logger.warn("Listener for interface {}: SocketException: {}.", interfaceContext.getDisplayName(), se.getMessage());
            }
            catch (IOException e) {
                if (isDiscoveryStarted && !Thread.currentThread().isInterrupted()) {
                    logger.warn("Listener for interface {}: IOException receiving discovery packet: {}", interfaceContext.getDisplayName(), e.getMessage());
                } else {
                    logger.info("Listener for interface {}: Interrupted or discovery stopped, terminating.", interfaceContext.getDisplayName());
                    break;
                }
            } catch (NumberFormatException nfe) {
                logger.warn("Listener for interface {}: Error parsing port number from a discovery packet.", interfaceContext.getDisplayName(), nfe);
            } catch (Exception e) {
                logger.error("Listener for interface {}: Unexpected error in listener loop: {}", interfaceContext.getDisplayName(), e.getMessage(), e);
            }
        }
        logger.info("Listener stopped for interface {} ({})", interfaceContext.getName(), interfaceContext.getDisplayName());
    }


    private void cleanupInactivePeers() {
        if (!isDiscoveryStarted && discoveredPeers.isEmpty()) return; // Optimization: if not started and no peers, nothing to do.
                                                                    // If started, always run. If stopped but peers exist, clean them.
        long now = System.currentTimeMillis();
        int removedCount = 0;
        for (Map.Entry<String, DiscoveredPeer> entry : discoveredPeers.entrySet()) {
            if (now - entry.getValue().getLastSeen() > PEER_TIMEOUT_MS) {
                discoveredPeers.remove(entry.getKey());
                logger.info("Removing inactive peer: {}", entry.getValue().getPeerId());
                removedCount++;
            }
        }
        if (removedCount > 0) {
            logger.debug("Cleaned up {} inactive peers.", removedCount);
        }
    }

    public synchronized void setLocalServicePort(int port) {
        this.localServicePort = port;
        logger.info("DeviceDiscoveryService: Local service port for P2P connections set to {}", port);
    }

    public Set<DiscoveredPeer> getDiscoveredPeers() {
        return new HashSet<>(discoveredPeers.values());
    }

    public DiscoveredPeer getPeerById(String peerId) {
        if (peerId == null || peerId.isEmpty()) {
            return null;
        }
        return discoveredPeers.get(peerId);
    }

    private String getMTUSafe(NetworkInterface ni) {
        try {
            return String.valueOf(ni.getMTU());
        } catch (SocketException e) {
            // This can happen on some virtual interfaces or if the interface is down
            // logger.trace("Could not get MTU for interface {}: {}", ni.getDisplayName(), e.getMessage());
            return "N/A";
        }
    }

    public static class DiscoveredPeer {
        private final String peerId;
        private final String ipAddress; // This is the IP address *advertised by the peer*
        private final int servicePort;
        private final long lastSeen;

        public DiscoveredPeer(String peerId, String ipAddress, int servicePort, long lastSeen) {
            this.peerId = peerId;
            this.ipAddress = ipAddress;
            this.servicePort = servicePort;
            this.lastSeen = lastSeen;
        }

        public String getPeerId() { return peerId; }
        public String getIpAddress() { return ipAddress; }
        public int getServicePort() { return servicePort; }
        public long getLastSeen() { return lastSeen; }

        @Override
        public String toString() {
            return "DiscoveredPeer{" +
                    "peerId='" + peerId + '\'' +
                    ", ipAddress='" + ipAddress + '\'' +
                    ", servicePort=" + servicePort +
                    ", lastSeen=" + lastSeen +
                    '}';
        }
    }
}
