// src/services/AuthService.ts

// Base URL for authentication endpoints
const API_AUTH_URL = 'http://localhost:8121/api/auth';

// --- Type Definitions ---

// Matches the User model from the backend (simplified for frontend use)
export interface User {
  userId: string;
  username: string;
  // Add other fields as needed, e.g., publicKey, createdAt, lastSeenAt
}

// Matches RegistrationRequest DTO from backend
export interface RegistrationData {
  username: string;
  deviceName?: string; // Optional, as per backend DTO
}

// Matches LoginRequest DTO from backend
export interface LoginData {
  username: string;
  deviceName?: string; // Optional
}

// Expected response structure for successful login/registration
// Assuming the backend returns the User object upon successful auth
export interface AuthResponse extends User {}

// Generic API error structure (can be shared across services)
interface ApiError {
  message: string;
  details?: any; // Or a more specific error structure from your backend
}

// --- API Functions ---

/**
 * Registers a new user.
 * @param registrationData The user registration data.
 * @returns A Promise that resolves to the User object if successful.
 * @throws ApiError if registration fails.
 */
export const register = async (registrationData: RegistrationData): Promise<User> => {
  console.log(`AuthService: Attempting registration for user: ${registrationData.username}`);
  try {
    const response = await fetch(`${API_AUTH_URL}/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(registrationData),
    });

    if (!response.ok) {
      const errorData: ApiError = await response.json().catch(() => ({ message: `Registration failed with status: ${response.status}` }));
      console.error('AuthService: Registration API error:', errorData);
      throw errorData; // Throw the structured error
    }

    const registeredUser: User = await response.json();
    console.log('AuthService: Registration successful:', registeredUser);
    return registeredUser;
  } catch (error) {
    console.error('AuthService: Error calling registration API:', error);
    if (error && typeof (error as ApiError).message === 'string') {
        throw error; // Re-throw if it's already an ApiError
    }
    throw { message: 'An unexpected error occurred during registration.' } as ApiError;
  }
};

/**
 * Logs in an existing user.
 * @param loginData The user login data.
 * @returns A Promise that resolves to the User object if successful.
 * @throws ApiError if login fails.
 */
export const login = async (loginData: LoginData): Promise<User> => {
  console.log(`AuthService: Attempting login for user: ${loginData.username}`);
  try {
    const response = await fetch(`${API_AUTH_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(loginData),
    });

    if (!response.ok) {
      const errorData: ApiError = await response.json().catch(() => ({ message: `Login failed with status: ${response.status}` }));
      console.error('AuthService: Login API error:', errorData);
      throw errorData;
    }

    const loggedInUser: User = await response.json();
    console.log('AuthService: Login successful:', loggedInUser);
    return loggedInUser;
  } catch (error) {
    console.error('AuthService: Error calling login API:', error);
     if (error && typeof (error as ApiError).message === 'string') {
        throw error;
    }
    throw { message: 'An unexpected error occurred during login.' } as ApiError;
  }
};

/**
 * Fetches the currently authenticated user's details.
 * @returns A Promise that resolves to the User object if authenticated, or null.
 * @throws ApiError if the request fails for reasons other than being unauthenticated.
 */
export const getCurrentUser = async (): Promise<User | null> => {
  console.log('AuthService: Attempting to fetch current user');
  try {
    const response = await fetch(`${API_AUTH_URL}/users/me`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        // Include credentials if your backend uses session cookies or similar
        // For token-based auth, you'd add an Authorization header here
      },
    });

    if (response.status === 401) { // Unauthorized
      console.log('AuthService: No authenticated user found (401).');
      return null;
    }

    if (!response.ok) {
      const errorData: ApiError = await response.json().catch(() => ({ message: `Failed to fetch current user with status: ${response.status}` }));
      console.error('AuthService: Get current user API error:', errorData);
      throw errorData;
    }

    const currentUser: User = await response.json();
    console.log('AuthService: Current user fetched successfully:', currentUser);
    return currentUser;
  } catch (error) {
    console.error('AuthService: Error calling get current user API:', error);
    if (error && typeof (error as ApiError).message === 'string') {
        throw error;
    }
    // Do not throw for 401, as that's a valid "no user" state.
    // For other errors, re-throw a generic one if it's not already an ApiError.
    throw { message: 'An unexpected error occurred while fetching current user.' } as ApiError;
  }
};

/**
 * Logs out the current user.
 * @returns A Promise that resolves if logout is successful.
 * @throws ApiError if logout fails.
 */
export const logout = async (): Promise<void> => {
  console.log('AuthService: Attempting logout');
  try {
    const response = await fetch(`${API_AUTH_URL}/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      // Try to parse error, but logout might return non-JSON on success/failure
      let errorData: ApiError = { message: `Logout failed with status: ${response.status}` };
      try {
        errorData = await response.json();
      } catch (e) {
        // If response is not JSON, use the status text or a generic message
        const textResponse = await response.text();
        errorData.message = textResponse || errorData.message;
      }
      console.error('AuthService: Logout API error:', errorData);
      throw errorData;
    }

    console.log('AuthService: Logout successful.');
    // No specific user data to return on logout
  } catch (error) {
    console.error('AuthService: Error calling logout API:', error);
    if (error && typeof (error as ApiError).message === 'string') {
        throw error;
    }
    throw { message: 'An unexpected error occurred during logout.' } as ApiError;
  }
};
