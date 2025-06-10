// src/pages/ChatPage.tsx
import React, { useState, ChangeEvent, FormEvent, useEffect, useRef } from 'react'; // Added useEffect, useRef
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { encryptMessageAPI, decryptMessageAPI } from '../services/MessageService';

interface Message {
  id: string;
  text: string;
  sender: 'user' | 'other' | 'system-info' | 'system-error'; // More specific system message types
  timestamp: Date;
}

const ChatPage: React.FC = () => {
  const { logout, userToken } = useAuth();
  const navigate = useNavigate();
  const [currentMessage, setCurrentMessage] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [isSending, setIsSending] = useState<boolean>(false);
  const chatAreaRef = useRef<HTMLDivElement>(null); // For auto-scrolling

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
    }
  }, [messages]);

  const addMessageToList = (text: string, sender: Message['sender']) => {
    setMessages(prevMessages => [
      ...prevMessages,
      {
        id: Date.now().toString() + Math.random().toString(36).substring(2, 7), // More unique ID
        text,
        sender,
        timestamp: new Date(),
      },
    ]);
  };

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
    setCurrentMessage('');

    // 1. Display user's original message (as user)
    addMessageToList(plainTextMessage, 'user');

    try {
      // 2. Encrypt the message via backend
      addMessageToList(`Encrypting "${plainTextMessage.substring(0,20)}..."`, 'system-info');
      const encryptedText = await encryptMessageAPI(plainTextMessage);
      addMessageToList(`Encrypted to: ${encryptedText.substring(0, 30)}...`, 'system-info');

      // 3. Decrypt the message via backend (simulating receiving and decrypting)
      addMessageToList(`Simulating reception & decryption of "${encryptedText.substring(0,20)}..."`, 'system-info');
      const decryptedText = await decryptMessageAPI(encryptedText);
      addMessageToList(`Received: ${decryptedText}`, 'other'); // Display as 'other' user

    } catch (error) {
      let errorMessage = 'An unknown error occurred.';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      console.error('ChatPage: Message processing error', error);
      addMessageToList(`Error: ${errorMessage}`, 'system-error');
    } finally {
      setIsSending(false);
    }
  };

  const getSenderStyle = (sender: Message['sender']) => {
    switch (sender) {
      case 'user':
        return { textAlign: 'right' as const, background: '#dcf8c6', color: 'black' };
      case 'other':
        return { textAlign: 'left' as const, background: '#f0f0f0', color: 'black' };
      case 'system-info':
        return { textAlign: 'center' as const, background: '#e0e0e0', color: '#555', fontStyle: 'italic' as const };
      case 'system-error':
        return { textAlign: 'center' as const, background: '#fdd', color: 'red', fontStyle: 'italic' as const };
      default:
        return { textAlign: 'left' as const, background: '#fff', color: 'black' };
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', padding: '10px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <h1>Chat Page</h1>
        <button onClick={handleLogout}>Logout</button>
      </div>
      <p style={{ margin: '0 0 10px 0' }}>
        Welcome! {userToken ? `(Token: ${userToken.substring(0,10)}...)` : ''}
      </p>

      <div
        ref={chatAreaRef}
        className="chat-area"
        style={{ flexGrow: 1, border: '1px solid #ccc', overflowY: 'auto', padding: '10px', marginBottom: '10px' }}
      >
        {messages.map((msg) => {
          const styles = getSenderStyle(msg.sender);
          return (
            <div key={msg.id} style={{ marginBottom: '8px', display: 'flex', justifyContent: styles.textAlign === 'right' ? 'flex-end' : (styles.textAlign === 'center' ? 'center' : 'flex-start') }}>
              <div style={{ maxWidth: '70%' }}> {/* Message bubble max width */}
                <span style={{
                  background: styles.background,
                  color: styles.color,
                  fontStyle: styles.fontStyle,
                  padding: '8px 12px',
                  borderRadius: '10px',
                  display: 'inline-block'
                }}>
                  {msg.text}
                  <div style={{ fontSize: '0.7em', color: styles.color === 'red' ? 'darkred' : '#777', marginTop: '3px', textAlign: 'right' }}>
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <form onSubmit={handleSendMessage} style={{ display: 'flex' }}>
        <input
          type="text"
          value={currentMessage}
          onChange={handleInputChange}
          placeholder="Type your message..."
          style={{ flexGrow: 1, padding: '10px', marginRight: '10px', borderRadius: '5px', border: '1px solid #ccc' }}
          disabled={isSending}
        />
        <button
          type="submit"
          style={{ padding: '10px 15px', borderRadius: '5px', border: 'none', background: '#007bff', color: 'white' }}
          disabled={isSending}
        >
          {isSending ? 'Sending...' : 'Send'}
        </button>
      </form>
    </div>
  );
};

export default ChatPage;
