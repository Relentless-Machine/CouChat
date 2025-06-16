// filepath: F:\Git\CouChat\couchat-frontend\src\services\P2PService.ts
import { API_BASE_URL } from '../config'; // Assuming you have a config file for API base URL

/**
 * Attempts to initiate a P2P connection with the specified peer.
 * @param peerId The ID of the peer to connect to.
 * @returns A promise that resolves with the server's response message.
 * @throws Will throw an error if the API call fails.
 */
export const connectToPeer = async (peerId: string): Promise<string> => {
  console.log(`P2PService: Attempting to connect to peer: ${peerId}`);
  try {
    const response = await fetch(`${API_BASE_URL}/api/p2p/connect/${peerId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Include Authorization header if your API requires authentication for this endpoint
        // 'Authorization': `Bearer ${your_auth_token_here}`,
      },
    });

    if (!response.ok) {
      const errorBody = await response.text(); // Or response.json() if error details are in JSON
      console.error(`P2PService: Failed to connect to peer ${peerId}. Status: ${response.status}, Body: ${errorBody}`);
      throw new Error(`Failed to connect to peer: ${response.status} - ${errorBody}`);
    }

    const successMessage = await response.text();
    console.log(`P2PService: Successfully initiated connection to peer ${peerId}. Response: ${successMessage}`);
    return successMessage;
  } catch (error) {
    console.error(`P2PService: Error connecting to peer ${peerId}:`, error);
    throw error; // Re-throw the error to be handled by the caller
  }
};

/**
 * Fetches the list of discovered peers from the backend.
 * @returns A promise that resolves with an array of discovered peers.
 * @throws Will throw an error if the API call fails.
 */
export interface DiscoveredPeer {
  peerId: string;
  username: string; // Assuming username is part of the peer info
  ipAddress: string;
  servicePort: number;
  // Add other relevant peer properties as defined by your backend
}

export const getDiscoveredPeers = async (): Promise<DiscoveredPeer[]> => {
  console.log('P2PService: Fetching discovered peers...');
  try {
    const response = await fetch(`${API_BASE_URL}/api/p2p/discovered-peers`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        // 'Authorization': `Bearer ${your_auth_token_here}`, // If needed
      },
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`P2PService: Failed to fetch discovered peers. Status: ${response.status}, Body: ${errorBody}`);
      throw new Error(`Failed to fetch discovered peers: ${response.status} - ${errorBody}`);
    }

    const peers: DiscoveredPeer[] = await response.json();
    console.log('P2PService: Successfully fetched discovered peers:', peers);
    return peers;
  } catch (error) {
    console.error('P2PService: Error fetching discovered peers:', error);
    throw error;
  }
};

