// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState, ReactNode } from 'react';

// Define the shape of the auth context
interface AuthContextType {
  isAuthenticated: boolean;
  userToken: string | null;
  login: (token: string) => void;
  logout: () => void;
}

// Create the context with a default undefined value, as it will be provided by AuthProvider
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Define the props for the AuthProvider
interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [userToken, setUserToken] = useState<string | null>(null);

  const login = (token: string) => {
    setIsAuthenticated(true);
    setUserToken(token);
    // In a real app, you might store the token in localStorage or sessionStorage
    console.log('AuthContext: User logged in, token set.');
  };

  const logout = () => {
    setIsAuthenticated(false);
    setUserToken(null);
    // Clear token from storage if used
    console.log('AuthContext: User logged out.');
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, userToken, login, logout }}>
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

