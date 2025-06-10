// src/services/AuthService.ts

// Define a type for the login response for better type safety
interface LoginResponse {
  success: boolean;
  message: string;
  token?: string; // Optional: a mock token
}

/**
 * Simulates a login API call.
 * @param username The username.
 * @param password The password.
 * @returns A Promise that resolves to a LoginResponse object.
 */
export const login = async (username?: string, password?: string): Promise<LoginResponse> => {
  console.log(`AuthService: Attempting login for user: ${username}`);

  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Basic validation (can be expanded)
  if (!username || !password) {
    return {
      success: false,
      message: 'Username and password are required.',
    };
  }

  // Mock successful login for a specific user or any user for now
  // For a real app, this would involve an API call to the backend
  if (username === 'testuser' && password === 'password123') {
    return {
      success: true,
      message: 'Login successful!',
      token: 'mock-jwt-token-12345', // Simulate a JWT token
    };
  } else if (username === 'user' && password === 'pass') { // Another test user
     return {
      success: true,
      message: 'Login successful for user!',
      token: 'mock-jwt-token-67890',
    };
  }

  return {
    success: false,
    message: 'Invalid username or password.',
  };
};

