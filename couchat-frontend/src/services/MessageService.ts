// src/services/MessageService.ts

const API_BASE_URL = 'http://localhost:8080/api/messages'; // Assuming backend runs on port 8080

interface EncryptedResponse {
  encryptedText: string;
}

interface DecryptedResponse {
  plainText: string;
}

// Error type for API responses
interface ApiError {
  message: string; // Or a more structured error object from your backend
  details?: any;
}

/**
 * Calls the backend API to encrypt a plain text message.
 * @param plainText The plain text message to encrypt.
 * @returns A Promise that resolves to the encrypted text or an error message.
 */
export const encryptMessageAPI = async (plainText: string): Promise<string> => {
  try {
    const response = await fetch(`${API_BASE_URL}/encrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ plainText }),
    });

    if (!response.ok) {
      const errorData: ApiError = await response.json().catch(() => ({ message: response.statusText }));
      console.error('MessageService: Encryption API error:', errorData);
      throw new Error(`Encryption failed: ${errorData.message || response.statusText}`);
    }

    const data: EncryptedResponse = await response.json();
    return data.encryptedText;
  } catch (error) {
    console.error('MessageService: Error calling encryption API:', error);
    // Ensure a string is thrown for consistent error handling upstream
    if (error instanceof Error) {
        throw error;
    }
    throw new Error('An unexpected error occurred during encryption.');
  }
};

/**
 * Calls the backend API to decrypt an encrypted message.
 * @param encryptedText The Base64 encoded encrypted message.
 * @returns A Promise that resolves to the decrypted plain text or an error message.
 */
export const decryptMessageAPI = async (encryptedText: string): Promise<string> => {
  try {
    const response = await fetch(`${API_BASE_URL}/decrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ encryptedText }),
    });

    if (!response.ok) {
      const errorData: ApiError = await response.json().catch(() => ({ message: response.statusText }));
      console.error('MessageService: Decryption API error:', errorData);
      throw new Error(`Decryption failed: ${errorData.message || response.statusText}`);
    }

    const data: DecryptedResponse = await response.json();
    return data.plainText;
  } catch (error) {
    console.error('MessageService: Error calling decryption API:', error);
    if (error instanceof Error) {
        throw error;
    }
    throw new Error('An unexpected error occurred during decryption.');
  }
};

