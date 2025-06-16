// src/pages/ChatPage.tsx
import React, { useState, ChangeEvent, FormEvent, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import UserDiscoveryPanel from '../components/UserDiscoveryPanel';
import { DiscoveredPeer } from '../services/P2PService';
import {
  Message, // Correctly imported
  MessageType, // Correctly imported
  MessageStatus, // Import if needed for optimistic updates, already used in optimisticMessage
  sendMessage as sendMessageAPI,
  getMessagesByConversationIdAPI,
  markConversationAsReadAPI,
} from '../services/MessageService';

const ChatPage: React.FC = () => {
  const { logout, currentUser } = useAuth();
  const navigate = useNavigate();
  const [currentMessage, setCurrentMessage] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [isSending, setIsSending] = useState<boolean>(false);
  const chatAreaRef = useRef<HTMLDivElement>(null);

  const [currentChatPeer, setCurrentChatPeer] = useState<DiscoveredPeer | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<string>('Disconnected');
  const [chatError, setChatError] = useState<string | null>(null);
  const [replyingToMessage, setReplyingToMessage] = useState<Message | null>(null); // State for the message being replied to

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
    }
  }, [messages]);

  // const addMessageToList = (text: string, sender: Message['sender']) => { // This function is no longer used directly for adding chat messages
  //   setMessages(prevMessages => [
  //     ...prevMessages,
  //     {
  //       id: Date.now().toString() + Math.random().toString(36).substring(2, 7),
  //       text,
  //       sender,
  //       timestamp: new Date(),
  //     },
  //   ]);
  // };

  const addSystemMessage = (text: string, systemMessageType: 'system-info' | 'system-error') => {
    setMessages(prevMessages => [
      ...prevMessages,
      {
        id: `sys-${Date.now()}`,
        conversationId: currentChatPeer?.peerId || 'system',
        senderId: 'system',
        recipientId: currentUser?.userId || 'system',
        payload: text,
        type: MessageType.SYSTEM, // Use Enum
        timestamp: new Date(),    // Already a Date object
        status: MessageStatus.READ, // Use Enum
        originalMessageId: null,
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

  const handleStartReply = (message: Message) => {
    setReplyingToMessage(message);
    // Optionally, focus the input field here
    const inputField = document.getElementById('chat-message-input'); // Add an ID to your input field
    if (inputField) inputField.focus();
  };

  const handleCancelReply = () => {
    setReplyingToMessage(null);
  };

  // Fetch messages when currentChatPeer changes
  const fetchMessages = useCallback(async () => {
    if (!currentChatPeer || !currentUser) return;
    const conversationId = currentChatPeer.peerId;
    console.log(`ChatPage: Fetching messages for conversation with ${conversationId}`);
    try {
      const fetchedMessages = await getMessagesByConversationIdAPI(conversationId);
      // MessageService now ensures timestamp is a Date object.
      setMessages(fetchedMessages);
      markConversationAsReadAPI(conversationId).catch(err => console.error("Failed to mark conversation as read", err));
    } catch (error) {
      console.error('ChatPage: Error fetching messages:', error);
      setChatError('Failed to load messages.');
      addSystemMessage('Error fetching messages.', 'system-error');
    }
  }, [currentChatPeer, currentUser]);

  useEffect(() => {
    if (currentChatPeer) {
      fetchMessages();
      // Setup interval to poll for new messages
      const intervalId = setInterval(fetchMessages, 3000); // Poll every 3 seconds
      return () => clearInterval(intervalId); // Cleanup interval
    } else {
      setMessages([]); // Clear messages if no peer is selected
    }
  }, [currentChatPeer, fetchMessages]);

  const handleSendMessage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (currentMessage.trim() === '' || isSending || !currentChatPeer || !currentUser) {
      if (!currentChatPeer) addSystemMessage('No user selected to chat with.', 'system-error');
      return;
    }

    setIsSending(true);
    const textToSend = currentMessage;
    setCurrentMessage('');

    const optimisticMessage: Message = {
      id: `temp-${Date.now()}`,
      conversationId: currentChatPeer.peerId,
      senderId: currentUser.userId,
      recipientId: currentChatPeer.peerId,
      payload: textToSend,
      type: MessageType.TEXT,
      timestamp: new Date(),
      status: MessageStatus.SENT,
      originalMessageId: replyingToMessage ? replyingToMessage.id : null, // Add originalMessageId if replying
    };
    setMessages(prevMessages => [...prevMessages, optimisticMessage]);

    // Clear the replyingToMessage state after constructing the optimistic message
    if (replyingToMessage) {
      setReplyingToMessage(null);
    }

    try {
      const sentMessage = await sendMessageAPI({
        conversationId: currentChatPeer.peerId,
        recipientId: currentChatPeer.peerId,
        type: MessageType.TEXT,
        payload: textToSend,
        originalMessageId: optimisticMessage.originalMessageId, // Pass it to the API
      });
      setMessages(prevMessages =>
        prevMessages.map(msg => (msg.id === optimisticMessage.id ? { ...sentMessage, timestamp: new Date(sentMessage.timestamp) } : msg))
      );
    } catch (error) {
      let errorMessage = 'An unknown error occurred while sending.';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      console.error('ChatPage: Message sending error', error);
      addSystemMessage(`Error sending message: ${errorMessage}`, 'system-error');
      // Optionally, mark the optimistic message as failed
      setMessages(prevMessages =>
        prevMessages.map(msg => (msg.id === optimisticMessage.id ? { ...msg, status: MessageStatus.FAILED } : msg)) // Use Enum
      );
    } finally {
      setIsSending(false);
    }
  };

  const getSenderDisplayName = (senderId: string): string => {
    if (senderId === currentUser?.userId) return "You";
    if (senderId === currentChatPeer?.peerId) return currentChatPeer.username || currentChatPeer.peerId; // Display username if available
    if (senderId === 'system') return "System";
    return senderId; // Fallback to senderId
  };

  const getMessageStyle = (message: Message) => {
    if (message.senderId === 'system') {
      return {
        textAlign: 'center' as const,
        // Assuming system messages might have a different type for errors, though current addSystemMessage uses MessageType.SYSTEM
        background: message.payload.toLowerCase().includes('error') || message.payload.toLowerCase().includes('failed') ? '#fdd' : '#e0e0e0',
        color: message.payload.toLowerCase().includes('error') || message.payload.toLowerCase().includes('failed') ? 'red' : '#555',
        fontStyle: 'italic' as const,
      };
    }
    return {
      textAlign: message.senderId === currentUser?.userId ? 'right' as const : 'left' as const,
      background: message.senderId === currentUser?.userId ? '#dcf8c6' : '#f0f0f0',
      color: 'black',
    };
  };

  // Callbacks for UserDiscoveryPanel
  const handleSelectPeer = (peer: DiscoveredPeer) => {
    console.log('ChatPage: Peer selected for chat:', peer);
    // Connection is now initiated by UserDiscoveryPanel's connect button
    // We just set the peer here if connection was successful (handled by onConnectionSuccess)
    // setCurrentChatPeer(peer);
    // setConnectionStatus(`Connecting to ${peer.peerId}...`);
    // setMessages([]); // Clear previous chat messages
    // setChatError(null);
  };

  const handleConnectionAttempt = (peerId: string) => {
    setConnectionStatus(`Attempting to connect to ${peerId}...`);
    addSystemMessage(`Attempting to connect to ${peerId}...`, 'system-info');
    setCurrentChatPeer(null); // Clear current chat while attempting new connection
    setMessages([]);
  };

  const handleConnectionSuccess = (peer: DiscoveredPeer, message: string) => { // Changed peerId to peer: DiscoveredPeer
    setConnectionStatus(`Connected to ${peer.peerId}. ${message}`);
    addSystemMessage(`Successfully connected to ${peer.peerId}. ${message}`, 'system-info');
    setCurrentChatPeer(peer); // Use the full DiscoveredPeer object passed from UserDiscoveryPanel
  };

  const handleConnectionError = (peerId: string, errorMessage: string) => {
    setConnectionStatus(`Failed to connect to ${peerId}: ${errorMessage}`);
    addSystemMessage(`Connection to ${peerId} failed: ${errorMessage}`, 'system-error');
    setCurrentChatPeer(null);
  };

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Left Panel: User Discovery */}
      <div style={{ width: '300px', borderRight: '1px solid #ccc', padding: '10px', overflowY: 'auto' }}>
        <h2 style={{ marginTop: 0 }}>Discover Users</h2>
        <UserDiscoveryPanel
          onSelectPeer={handleSelectPeer} // This might be redundant if connection handles selection
          currentChatPeerId={currentChatPeer?.peerId}
          onConnectionAttempt={handleConnectionAttempt}
          onConnectionSuccess={handleConnectionSuccess}
          onConnectionError={handleConnectionError}
        />
        <button
          onClick={handleLogout}
          style={{ marginTop: '20px', padding: '8px 15px', borderRadius: '5px', border: 'none', background: '#dc3545', color: 'white', cursor: 'pointer', width: '100%' }}
        >
          Logout
        </button>
      </div>

      {/* Right Panel: Chat Area */}
      <div style={{ flexGrow: 1, display: 'flex', flexDirection: 'column', padding: '10px' }}>
        {/* Header Section */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '15px',
          paddingBottom: '10px',
          borderBottom: '1px solid #eee'
        }}>
          <h1 style={{ margin: 0, fontSize: '1.5em' }}>
            {currentChatPeer ? `Chat with ${currentChatPeer.username || currentChatPeer.peerId}` : 'Select a user to chat'}
          </h1>
          <span style={{fontSize: '0.9em', color: '#666'}}>{connectionStatus}</span>
        </div>

        {/* Chat Messages Area */}
        <div
          ref={chatAreaRef}
          className="chat-area"
          style={{ flexGrow: 1, border: '1px solid #ccc', overflowY: 'auto', padding: '10px', marginBottom: '10px', backgroundColor: '#f9f9f9' }}
        >
          {messages.map((msg) => {
            const styles = getMessageStyle(msg);
            const displayName = getSenderDisplayName(msg.senderId);
            const isSystemMessage = msg.senderId === 'system';
            const isMyMessage = msg.senderId === currentUser?.userId;

            // Find the original message if this is a reply
            let originalMsgDisplay = null;
            if (msg.originalMessageId) {
              const original = messages.find(m => m.id === msg.originalMessageId);
              if (original) {
                originalMsgDisplay = (
                  <div style={{
                    fontSize: '0.8em',
                    padding: '5px 8px',
                    background: styles.textAlign === 'right' ? '#cce5ff' : '#e9e9e9',
                    borderRadius: '5px',
                    marginBottom: '4px',
                    borderLeft: `3px solid ${styles.textAlign === 'right' ? '#99c2ff' : '#ccc'}`,
                    opacity: 0.8
                  }}>
                    <strong>{getSenderDisplayName(original.senderId)}:</strong>
                    <span style={{ marginLeft: '5px', fontStyle: 'italic' }}>
                      {original.payload.length > 60 ? original.payload.substring(0, 57) + '...' : original.payload}
                    </span>
                  </div>
                );
              }
            }

            return (
              <div key={msg.id} style={{ marginBottom: '8px', display: 'flex', justifyContent: styles.textAlign === 'right' ? 'flex-end' : (styles.textAlign === 'center' ? 'center' : 'flex-start') }}>
                <div style={{ maxWidth: '70%', display: 'flex', flexDirection: styles.textAlign === 'right' ? 'row-reverse' : 'row', alignItems: 'flex-end' }}>
                  <div style={{ /* This div now wraps the message bubble and the potential replied message quote */
                    order: styles.textAlign === 'right' ? 1 : 0,
                  }}>
                    {originalMsgDisplay} {/* Display the original message quote if it exists */}
                    <span style={{
                      background: styles.background,
                      color: styles.color,
                      fontStyle: styles.fontStyle,
                      padding: '8px 12px',
                      borderRadius: '10px',
                      display: 'inline-block',
                      wordBreak: 'break-word',
                      order: styles.textAlign === 'right' ? 1 : 0, // Ensures message bubble is on the correct side of reply button for user messages
                    }}>
                      <div style={{ fontSize: '0.8em', color: '#555', marginBottom: '2px', textAlign: styles.textAlign === 'right' ? 'right' : 'left'}}>
                        {displayName}
                      </div>
                      {msg.payload} {/* Changed from msg.text to msg.payload */}
                      <div style={{ fontSize: '0.7em', color: styles.color === 'red' ? 'darkred' : '#777', marginTop: '3px', textAlign: 'right' }}>
                        {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        {msg.status === MessageStatus.SENT && ' ✓'}
                        {msg.status === MessageStatus.DELIVERED && ' ✓✓'}
                        {msg.status === MessageStatus.READ && <span style={{color: 'blue'}}>✓✓</span>}
                        {msg.status === MessageStatus.FAILED && ' ✗'}
                      </div>
                    </span>
                    {!isSystemMessage && msg.status !== MessageStatus.PENDING && msg.status !== MessageStatus.FAILED && (
                      <button
                        onClick={() => handleStartReply(msg)}
                        style={{
                          marginLeft: styles.textAlign === 'left' ? '8px' : '0',
                          marginRight: styles.textAlign === 'right' ? '8px' : '0',
                          padding: '2px 6px',
                          fontSize: '0.7em',
                          cursor: 'pointer',
                          border: '1px solid #ccc',
                          borderRadius: '4px',
                          background: '#f0f0f0',
                          order: styles.textAlign === 'right' ? 0 : 1, // Ensures reply button is on the correct side
                          alignSelf: 'center', // Vertically center the button a bit better
                        }}
                        title="Reply to this message"
                      >
                        ↪
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
          {chatError && <p style={{color: 'red', textAlign: 'center'}}>{chatError}</p>}
        </div>

        {/* Replying-to Banner */}
        {replyingToMessage && (
          <div style={{
            padding: '8px 10px',
            background: '#f0f0f0',
            border: '1px solid #ddd',
            borderRadius: '4px',
            marginBottom: '10px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.9em'
          }}>
            <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              Replying to:
              <strong style={{ marginLeft: '5px' }}>{getSenderDisplayName(replyingToMessage.senderId)}</strong>
              <em style={{ marginLeft: '5px', color: '#555' }}>
                {replyingToMessage.payload.length > 50 ? replyingToMessage.payload.substring(0, 47) + '...' : replyingToMessage.payload}
              </em>
            </div>
            <button
              onClick={handleCancelReply}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#777',
                cursor: 'pointer',
                fontSize: '1.2em',
                padding: '0 5px'
              }}
              title="Cancel reply"
            >
              &times;
            </button>
          </div>
        )}

        {/* Message Input Form */}
        <form onSubmit={handleSendMessage} style={{ display: 'flex', marginTop: 'auto' }}>
          <input
            id="chat-message-input" // Added ID for focusing
            type="text"
            value={currentMessage}
            onChange={handleInputChange}
            placeholder={currentChatPeer ? `Message ${currentChatPeer.username || currentChatPeer.peerId}` : "Select a user to start chatting"}
            style={{ flexGrow: 1, padding: '10px', marginRight: '10px', borderRadius: '5px', border: '1px solid #ccc' }}
            disabled={isSending || !currentChatPeer}
          />
          <button
            type="submit"
            style={{ padding: '10px 15px', borderRadius: '5px', border: 'none', background: '#007bff', color: 'white', cursor: 'pointer' }}
            disabled={isSending || !currentChatPeer}
          >
            {isSending ? 'Sending...' : 'Send'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default ChatPage;
