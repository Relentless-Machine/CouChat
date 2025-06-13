package com.couchat.p2p;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class DeviceDiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DeviceDiscoveryService.class);
    private static final String MULTICAST_ADDRESS = "230.0.0.1"; // Example multicast address
    private static final int DISCOVERY_PORT = 8888; // Example discovery port
    private static final int BROADCAST_INTERVAL_MS = 5000; // Broadcast every 5 seconds
    private static final int PEER_TIMEOUT_MS = 15000; // Peer considered offline after 15 seconds

    private MulticastSocket multicastSocket;
    private DatagramSocket unicastSocket; // For responding to discovery requests or direct communication
    private InetAddress group;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private final ConcurrentHashMap<String, DiscoveredPeer> discoveredPeers = new ConcurrentHashMap<>();
    private String localPeerId; // Unique ID for this device, could be username or generated ID
    private int localServicePort; // The port on which main P2P services are running

    @PostConstruct
    public void init() {
        try {
            localPeerId = InetAddress.getLocalHost().getHostName() + "_" + System.currentTimeMillis(); // Simple unique ID
            // It's better to get the actual service port from configuration or another service
            // For now, let's assume a placeholder or that it will be set
            localServicePort = 9090; // Placeholder for actual P2P service port

            group = InetAddress.getByName(MULTICAST_ADDRESS);

            // Setup MulticastSocket for discovery
            multicastSocket = new MulticastSocket(DISCOVERY_PORT);
            multicastSocket.joinGroup(group); // Join the multicast group
            logger.info("Joined multicast group {} on port {}", MULTICAST_ADDRESS, DISCOVERY_PORT);

            // Setup UnicastSocket for potential direct responses if needed (optional for pure discovery)
            unicastSocket = new DatagramSocket(); // Or a specific port if it needs to be known
            logger.info("Unicast socket started on port {}", unicastSocket.getLocalPort());


            scheduler.scheduleAtFixedRate(this::broadcastPresence, 0, BROADCAST_INTERVAL_MS, TimeUnit.MILLISECONDS);
            scheduler.execute(this::listenForPeers);
            scheduler.scheduleAtFixedRate(this::cleanupInactivePeers, PEER_TIMEOUT_MS, PEER_TIMEOUT_MS, TimeUnit.MILLISECONDS);

            logger.info("DeviceDiscoveryService initialized. Local Peer ID: {}", localPeerId);

        } catch (UnknownHostException e) {
            logger.error("Multicast address unknown: {}", MULTICAST_ADDRESS, e);
        } catch (SocketException e) {
            logger.error("SocketException during P2P discovery service initialization. Check if port {} is in use or network configuration.", DISCOVERY_PORT, e);
        }
        catch (IOException e) {
            logger.error("IOException during P2P discovery service initialization", e);
        }
    }

    private void broadcastPresence() {
        try {
            String localIp = getLocalIpAddress();
            if (localIp == null) {
                logger.warn("Could not determine local IP address for broadcasting presence.");
                return;
            }
            // Message format: PEER_ID:IP_ADDRESS:SERVICE_PORT
            String message = String.format("%s:%s:%d", localPeerId, localIp, localServicePort);
            byte[] buffer = message.getBytes();
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, group, DISCOVERY_PORT);
            multicastSocket.send(packet);
            logger.debug("Broadcasted presence: {}", message);
        } catch (IOException e) {
            logger.warn("Error broadcasting presence", e);
        }
    }

    private void listenForPeers() {
        byte[] buffer = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        while (!Thread.currentThread().isInterrupted() && multicastSocket != null && !multicastSocket.isClosed()) {
            try {
                multicastSocket.receive(packet);
                String message = new String(packet.getData(), 0, packet.getLength());
                logger.debug("Received discovery packet from {}:{} - {}", packet.getAddress().getHostAddress(), packet.getPort(), message);

                String[] parts = message.split(":");
                if (parts.length == 3) {
                    String peerId = parts[0];
                    String peerIp = parts[1]; // The IP from the message payload
                    int peerServicePort = Integer.parseInt(parts[2]);

                    // Ignore self-broadcasts
                    if (peerId.equals(localPeerId)) {
                        continue;
                    }

                    DiscoveredPeer peer = new DiscoveredPeer(peerId, peerIp, peerServicePort, System.currentTimeMillis());
                    discoveredPeers.put(peerId, peer);
                    logger.info("Discovered or updated peer: {}", peer);

                } else {
                    logger.warn("Received malformed discovery packet: {}", message);
                }
            } catch (SocketException se) {
                if (multicastSocket.isClosed()) {
                    logger.info("Multicast socket closed, stopping listener.");
                    break;
                }
                logger.error("SocketException in listener, may indicate socket closure: {}", se.getMessage());
            }
            catch (IOException e) {
                if (!Thread.currentThread().isInterrupted()) {
                    logger.warn("Error receiving discovery packet", e);
                } else {
                    logger.info("Listener interrupted, shutting down.");
                    break;
                }
            }
        }
        logger.info("Peer listener thread stopped.");
    }

    private String getLocalIpAddress() {
        try {
            // Prefer non-loopback, site-local addresses
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface ni = networkInterfaces.nextElement();
                if (ni.isLoopback() || !ni.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> inetAddresses = ni.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = inetAddresses.nextElement();
                    if (!inetAddress.isLoopbackAddress() && inetAddress.isSiteLocalAddress() && inetAddress.getHostAddress().indexOf(":") == -1) { // IPv4
                        return inetAddress.getHostAddress();
                    }
                }
            }
            // Fallback if no ideal address found
            return InetAddress.getLocalHost().getHostAddress();
        } catch (SocketException | UnknownHostException e) {
            logger.error("Failed to get local IP address", e);
            return null;
        }
    }


    private void cleanupInactivePeers() {
        long now = System.currentTimeMillis();
        discoveredPeers.entrySet().removeIf(entry -> {
            if (now - entry.getValue().getLastSeen() > PEER_TIMEOUT_MS) {
                logger.info("Removing inactive peer: {}", entry.getValue().getPeerId());
                return true;
            }
            return false;
        });
    }

    public Set<DiscoveredPeer> getDiscoveredPeers() {
        return new HashSet<>(discoveredPeers.values());
    }

    public DiscoveredPeer getPeerById(String peerId) {
        return discoveredPeers.get(peerId);
    }

    public void setLocalServicePort(int port) {
        this.localServicePort = port;
        // Potentially re-broadcast immediately with new info if needed
        // broadcastPresence();
    }

    public String getLocalPeerId() {
        return localPeerId;
    }

    @PreDestroy
    public void shutdown() {
        logger.info("Shutting down DeviceDiscoveryService...");
        scheduler.shutdownNow(); // Interrupt running tasks
        if (multicastSocket != null && !multicastSocket.isClosed()) {
            try {
                multicastSocket.leaveGroup(group);
                multicastSocket.close();
                logger.info("Multicast socket left group and closed.");
            } catch (IOException e) {
                logger.warn("Error closing multicast socket", e);
            }
        }
        if (unicastSocket != null && !unicastSocket.isClosed()) {
            unicastSocket.close();
            logger.info("Unicast socket closed.");
        }
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("Scheduler did not terminate in time.");
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
        logger.info("DeviceDiscoveryService shut down.");
    }

    // Inner class to represent a discovered peer
    public static class DiscoveredPeer {
        private final String peerId;
        private final String ipAddress;
        private final int servicePort;
        private long lastSeen;

        public DiscoveredPeer(String peerId, String ipAddress, int servicePort, long lastSeen) {
            this.peerId = peerId;
            this.ipAddress = ipAddress;
            this.servicePort = servicePort;
            this.lastSeen = lastSeen;
        }

        public String getPeerId() {
            return peerId;
        }

        public String getIpAddress() {
            return ipAddress;
        }

        public int getServicePort() {
            return servicePort;
        }

        public long getLastSeen() {
            return lastSeen;
        }

        public void setLastSeen(long lastSeen) {
            this.lastSeen = lastSeen;
        }

        @Override
        public String toString() {
            return "DiscoveredPeer{" +
                    "peerId='" + peerId + ''' +
                    ", ipAddress='" + ipAddress + ''' +
                    ", servicePort=" + servicePort +
                    ", lastSeen=" + lastSeen +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DiscoveredPeer that = (DiscoveredPeer) o;
            return peerId.equals(that.peerId);
        }

        @Override
        public int hashCode() {
            return peerId.hashCode();
        }
    }
}

