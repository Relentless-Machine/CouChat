// src/pages/ChatPage.tsx
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const ChatPage: React.FC = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
    console.log('ChatPage: User logged out and redirected to login.');
  };

  return (
    <div>
      <h1>Chat Page</h1>
      <p>Welcome to the chat!</p>
      {/* Chat interface will go here */}
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
};

export default ChatPage;
