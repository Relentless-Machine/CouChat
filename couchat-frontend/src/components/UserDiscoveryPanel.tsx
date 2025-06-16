import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { DiscoveredPeer, getDiscoveredPeers, connectToPeer } from '../services/P2PService'; // Import the service

// Define the structure of a Discovered Peer, matching backend DeviceDiscoveryService.DiscoveredPeer
// interface DiscoveredPeer { // Now imported from P2PService
//   peerId: string;
//   ipAddress: string;
//   servicePort: number;
//   // lastSeen: number; // Not strictly needed for selection, but good for info
// }

interface UserDiscoveryPanelProps {
  onSelectPeer: (peer: DiscoveredPeer) => void; // Callback when a peer is selected
  currentChatPeerId?: string | null; // Optional: to indicate who the user is currently chatting with
  onConnectionAttempt: (peerId: string) => void; // Callback when a connection attempt is initiated
  onConnectionSuccess: (peer: DiscoveredPeer, message: string) => void; // Changed peerId to peer: DiscoveredPeer
  onConnectionError: (peerId: string, errorMessage: string) => void; // Callback for connection error
}

// const API_P2P_URL = 'http://localhost:8121/api/p2p'; // No longer needed, using P2PService

const UserDiscoveryPanel: React.FC<UserDiscoveryPanelProps> = ({
  onSelectPeer,
  currentChatPeerId,
  onConnectionAttempt,
  onConnectionSuccess,
  onConnectionError,
}) => {
  const { currentUser } = useAuth();
  const [discoveredPeers, setDiscoveredPeers] = useState<DiscoveredPeer[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connectingPeerId, setConnectingPeerId] = useState<string | null>(null);

  const fetchDiscoveredPeers = useCallback(async () => {
    if (!currentUser) return;

    setIsLoading(true);
    setError(null);
    try {
      // const response = await fetch(`${API_P2P_URL}/discovered-peers`);
      // if (!response.ok) {
      //   const errorData = await response.json().catch(() => ({ message: `Failed to fetch peers: ${response.statusText}` }));
      //   throw new Error(errorData.message || `Failed to fetch peers: ${response.statusText}`);
      // }
      // const peers: DiscoveredPeer[] = await response.json();
      const peers = await getDiscoveredPeers(); // Use the service
      const otherPeers = peers.filter(peer => peer.peerId !== currentUser.userId);
      setDiscoveredPeers(otherPeers);
      console.log('UserDiscoveryPanel: Fetched discovered peers:', otherPeers);
    } catch (err: any) {
      console.error('UserDiscoveryPanel: Error fetching discovered peers:', err);
      setError(err.message || 'Could not fetch discovered users.');
      setDiscoveredPeers([]);
    }
    setIsLoading(false);
  }, [currentUser]);

  useEffect(() => {
    fetchDiscoveredPeers();
    const intervalId = setInterval(fetchDiscoveredPeers, 5000);
    return () => clearInterval(intervalId);
  }, [fetchDiscoveredPeers]);

  const handleConnectToPeer = async (peer: DiscoveredPeer) => {
    if (!currentUser) {
      setError('You must be logged in to connect to a peer.');
      return;
    }
    setConnectingPeerId(peer.peerId);
    onConnectionAttempt(peer.peerId);
    try {
      const successMessage = await connectToPeer(peer.peerId); // Use the service
      console.log(`UserDiscoveryPanel: Successfully initiated connection to ${peer.peerId}: ${successMessage}`);
      onConnectionSuccess(peer, successMessage); // Pass the full peer object
      onSelectPeer(peer); // Proceed to select the peer for chat
    } catch (err: any) {
      console.error(`UserDiscoveryPanel: Error connecting to peer ${peer.peerId}:`, err);
      setError(`Failed to connect to ${peer.peerId}: ${err.message}`);
      onConnectionError(peer.peerId, err.message || 'Unknown error during connection');
    }
    setConnectingPeerId(null);
  };

  if (!currentUser) {
    return <p>Please log in to discover other users.</p>;
  }

  return (
    <div style={{ border: '1px solid #ccc', padding: '15px', margin: '10px', borderRadius: '5px' }}>
      <h3>Discover Users on LAN</h3>
      {isLoading && discoveredPeers.length === 0 && <p>Discovering users...</p>}
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      {!isLoading && !error && discoveredPeers.length === 0 && (
        <p>No other users found on the network. Make sure other CouChat instances are running.</p>
      )}
      {discoveredPeers.length > 0 && (
        <ul style={{ listStyleType: 'none', padding: 0 }}>
          {discoveredPeers.map((peer) => (
            <li key={peer.peerId} style={{ marginBottom: '10px', padding: '8px', border: '1px solid #eee', borderRadius: '4px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>
                User: {peer.peerId} <br />
                {/* Display username if available, otherwise peerId */}
                {/* <small>Username: {peer.username || 'N/A'}</small><br /> */}
                <small>({peer.ipAddress}:{peer.servicePort})</small>
              </span>
              <button
                onClick={() => handleConnectToPeer(peer)} // Updated onClick handler
                disabled={currentChatPeerId === peer.peerId || connectingPeerId === peer.peerId} // Disable if already chatting or connecting
              >
                {currentChatPeerId === peer.peerId
                  ? 'Chatting'
                  : connectingPeerId === peer.peerId
                  ? 'Connecting...'
                  : 'Chat'}
              </button>
            </li>
          ))}
        </ul>
      )}
      <button onClick={fetchDiscoveredPeers} disabled={isLoading} style={{marginTop: '10px'}}>
        {isLoading ? 'Refreshing...' : 'Refresh User List'}
      </button>
    </div>
  );
};

export default UserDiscoveryPanel;
