// LoginPage.tsx
import React from 'react';
import LoginForm from '../components/LoginForm';
import { useAuth } from '../contexts/AuthContext';
import { Navigate } from 'react-router-dom';

const LoginPage: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <div style={{ textAlign: 'center', marginTop: '50px' }}>Loading authentication status...</div>;
  }

  if (isAuthenticated) {
    return <Navigate to="/chat" replace />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: '20px' }}>
      <LoginForm />
    </div>
  );
};

export default LoginPage;
