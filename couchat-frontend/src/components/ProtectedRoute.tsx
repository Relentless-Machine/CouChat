// src/components/ProtectedRoute.tsx
import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const ProtectedRoute: React.FC = () => {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    // User not authenticated, redirect to login page
    return <Navigate to="/login" replace />;
  }

  // User authenticated, render the child routes/components
  return <Outlet />;
};

export default ProtectedRoute;

