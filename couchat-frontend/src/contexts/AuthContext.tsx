// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, ReactNode, useEffect } from 'react';
import {
  User,
  LoginData,
  RegistrationData,
  login as apiLogin,
  register as apiRegister,
  getCurrentUser as apiGetCurrentUser,
  logout as apiLogout,
} from '../services/AuthService'; // Import User and functions from AuthService

// Define the shape of the auth context
interface AuthContextType {
  isAuthenticated: boolean;
  currentUser: User | null;
  isLoading: boolean; // To indicate if auth status is being checked
  login: (loginData: LoginData) => Promise<void>;
  register: (registrationData: RegistrationData) => Promise<void>;
  logout: () => Promise<void>;
  checkAuthStatus: () => Promise<void>; // Renamed for clarity
}

// Create the context with a default undefined value
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Define the props for the AuthProvider
interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true); // Start with loading true

  const checkAuthStatus = async () => {
    setIsLoading(true);
    try {
      console.log('AuthContext: Checking authentication status...');
      const user = await apiGetCurrentUser();
      if (user) {
        setCurrentUser(user);
        setIsAuthenticated(true);
        console.log('AuthContext: User is authenticated via checkAuthStatus.', user);
      } else {
        setCurrentUser(null);
        setIsAuthenticated(false);
        console.log('AuthContext: No authenticated user found via checkAuthStatus.');
      }
    } catch (error) {
      console.error('AuthContext: Error checking auth status:', error);
      setCurrentUser(null);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  // Check auth status when the provider mounts
  useEffect(() => {
    checkAuthStatus();
  }, []);

  const login = async (loginData: LoginData) => {
    setIsLoading(true);
    try {
      const user = await apiLogin(loginData);
      setCurrentUser(user);
      setIsAuthenticated(true);
      console.log('AuthContext: User logged in successfully.', user);
    } catch (error) {
      console.error('AuthContext: Login failed:', error);
      setCurrentUser(null);
      setIsAuthenticated(false);
      throw error; // Re-throw to allow LoginPage to handle it
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (registrationData: RegistrationData) => {
    setIsLoading(true);
    try {
      const user = await apiRegister(registrationData);
      setCurrentUser(user);
      setIsAuthenticated(true);
      console.log('AuthContext: User registered and logged in successfully.', user);
    } catch (error) {
      console.error('AuthContext: Registration failed:', error);
      setCurrentUser(null);
      setIsAuthenticated(false);
      throw error; // Re-throw to allow LoginPage to handle it
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await apiLogout();
      setCurrentUser(null);
      setIsAuthenticated(false);
      console.log('AuthContext: User logged out.');
    } catch (error) {
      console.error('AuthContext: Logout failed:', error);
      // Even if API logout fails, clear client-side state
      setCurrentUser(null);
      setIsAuthenticated(false);
      throw error; // Re-throw to allow UI to handle it if needed
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, currentUser, isLoading, login, register, logout, checkAuthStatus }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use the auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
