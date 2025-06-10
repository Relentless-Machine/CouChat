// src/pages/ChatPage.tsx
import React, { useState, ChangeEvent, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { encryptMessageAPI, decryptMessageAPI } from '../services/MessageService'; // Import message services

// Define a type for individual messages
interface Message {
  id: string; // Unique ID for each message
  text: string;
  sender: 'user' | 'other' | 'system'; // Added 'system' for status/error messages
  timestamp: Date;
  isEncrypted?: boolean; // Optional: to mark if the displayed text is encrypted
}

const ChatPage: React.FC = () => {
  const { logout, userToken } = useAuth(); // Assuming userToken might be useful later
  const navigate = useNavigate();
  const [currentMessage, setCurrentMessage] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [isSending, setIsSending] = useState<boolean>(false); // For send button loading state

  const handleLogout = () => {
    logout();
    navigate('/login');
    console.log('ChatPage: User logged out and redirected to login.');
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    setCurrentMessage(event.target.value);
  };

  const handleSendMessage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (currentMessage.trim() === '' || isSending) return;

    setIsSending(true);
    const plainTextMessage = currentMessage;
    setCurrentMessage(''); // Clear input immediately

    // 1. Display user's original message
    const sentMessage: Message = {
      id: Date.now().toString() + '-sent',
      text: `You sent: ${plainTextMessage}`,
      sender: 'user',
      timestamp: new Date(),
    };
    setMessages(prevMessages => [...prevMessages, sentMessage]);

    try {
      // 2. Encrypt the message via backend
      const encryptedText = await encryptMessageAPI(plainTextMessage);
      const encryptedInfoMessage: Message = {
        id: Date.now().toString() + '-encrypted',
        text: `Encrypted: ${encryptedText.substring(0, 30)}... (Full: ${encryptedText})`,
        sender: 'system',
        timestamp: new Date(),
        isEncrypted: true,
      };
      setMessages(prevMessages => [...prevMessages, encryptedInfoMessage]);

      // 3. Decrypt the message via backend (simulating receiving and decrypting)
      try {
        const decryptedText = await decryptMessageAPI(encryptedText);
        const receivedMessage: Message = {
          id: Date.now().toString() + '-decrypted',
          text: `Simulated received (decrypted): ${decryptedText}`,
          sender: 'other',
          timestamp: new Date(),
        };
        setMessages(prevMessages => [...prevMessages, receivedMessage]);
      } catch (decryptionError) {
        console.error('ChatPage: Decryption failed', decryptionError);
        const decryptErrorMessage: Message = {
          id: Date.now().toString() + '-dec-error',
          text: `Decryption Error: ${decryptionError instanceof Error ? decryptionError.message : 'Unknown error'}`,
          sender: 'system',
          timestamp: new Date(),
        };
        setMessages(prevMessages => [...prevMessages, decryptErrorMessage]);
      }

    } catch (encryptionError) {
      console.error('ChatPage: Encryption failed', encryptionError);
      const encryptErrorMessage: Message = {
        id: Date.now().toString() + '-enc-error',
        text: `Encryption Error: ${encryptionError instanceof Error ? encryptionError.message : 'Unknown error'}`,
        sender: 'system',
        timestamp: new Date(),
      };
      setMessages(prevMessages => [...prevMessages, encryptErrorMessage]);
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div>
      <h1>Chat Page</h1>
      <p>Welcome! {userToken ? `(Logged in with token: ${userToken.substring(0,10)}...)` : ''}</p>
      <button onClick={handleLogout}>Logout</button>

      <div className="chat-area" style={{ height: '300px', border: '1px solid #ccc', overflowY: 'auto', padding: '10px', marginBottom: '10px' }}>
        {messages.map((msg) => (
          <div key={msg.id} style={{
            textAlign: msg.sender === 'user' ? 'right' : (msg.sender === 'system' ? 'center' : 'left'),
            marginBottom: '5px',
            color: msg.sender === 'system' ? 'grey' : 'black'
          }}>
            <span style={{
              background: msg.sender === 'user' ? '#dcf8c6' : (msg.sender === 'system' ? '#e0e0e0' : '#f0f0f0'),
              padding: '5px 10px',
              borderRadius: '7px',
              fontStyle: msg.sender === 'system' ? 'italic' : 'normal'
            }}>
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
        <button type="submit" style={{ width: '60px', padding: '10px' }} disabled={isSending}>
          {isSending ? 'Sending...' : 'Send'}
        </button>
      </form>
    </div>
  );
};

export default ChatPage;
