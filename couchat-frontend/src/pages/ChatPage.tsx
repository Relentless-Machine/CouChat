// src/pages/ChatPage.tsx
import React, { useState, ChangeEvent, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

// Define a type for individual messages
interface Message {
  id: string; // Unique ID for each message
  text: string;
  sender: 'user' | 'other'; // To differentiate user's messages from others (or self for now)
  timestamp: Date;
}

const ChatPage: React.FC = () => {
  const { logout, userToken } = useAuth(); // Assuming userToken might be useful later
  const navigate = useNavigate();
  const [currentMessage, setCurrentMessage] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);

  const handleLogout = () => {
    logout();
    navigate('/login');
    console.log('ChatPage: User logged out and redirected to login.');
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    setCurrentMessage(event.target.value);
  };

  const handleSendMessage = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (currentMessage.trim() === '') return; // Don't send empty messages

    const newMessage: Message = {
      id: Date.now().toString(), // Simple unique ID for now
      text: currentMessage,
      sender: 'user', // Mark as sent by the current user
      timestamp: new Date(),
    };

    setMessages(prevMessages => [...prevMessages, newMessage]);
    setCurrentMessage(''); // Clear the input field
    console.log('ChatPage: Message sent:', newMessage);

    // TODO: Later, call backend to encrypt and send, then simulate receiving
  };

  return (
    <div>
      <h1>Chat Page</h1>
      <p>Welcome! {userToken ? `(Logged in with token: ${userToken.substring(0,10)}...)` : ''}</p>
      <button onClick={handleLogout}>Logout</button>

      <div className="chat-area" style={{ height: '300px', border: '1px solid #ccc', overflowY: 'auto', padding: '10px', marginBottom: '10px' }}>
        {messages.map((msg) => (
          <div key={msg.id} style={{ textAlign: msg.sender === 'user' ? 'right' : 'left', marginBottom: '5px' }}>
            <span style={{ background: msg.sender === 'user' ? '#dcf8c6' : '#f0f0f0', padding: '5px 10px', borderRadius: '7px' }}>
              {msg.text}
              <br />
              <small style={{ fontSize: '0.7em' }}>
                {msg.timestamp.toLocaleTimeString()}
              </small>
            </span>
          </div>
        ))}
      </div>

      <form onSubmit={handleSendMessage} className="message-input-form">
        <input
          type="text"
          value={currentMessage}
          onChange={handleInputChange}
          placeholder="Type your message..."
          style={{ width: 'calc(100% - 70px)', padding: '10px' }}
        />
        <button type="submit" style={{ width: '60px', padding: '10px' }}>Send</button>
      </form>
    </div>
  );
};

export default ChatPage;
