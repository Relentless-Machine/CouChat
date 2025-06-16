// src/pages/ChatPage.tsx
import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import UserDiscoveryPanel from '../components/UserDiscoveryPanel';
import type { DiscoveredPeer } from '../services/P2PService';
import {
  MessageType,
  MessageStatus,
  sendMessage as sendMessageAPI,
  getMessagesByConversationIdAPI,
  markConversationAsReadAPI,
} from '../services/MessageService';
import type { Message, SendMessageDTO } from '../services/MessageService';

// Helper function to determine a canonical conversation ID
const determineP2PConversationId = (userId1: string, userId2: string): string => {
  if (!userId1 || !userId2) {
    console.error("User ID is null or empty for determining P2P conversation ID. User1:", userId1, "User2:", userId2);
    return `p2p_error_invalid_ids_${Date.now()}`;
  }
  const ids = [userId1, userId2].sort();
  return `p2p_${ids[0]}_${ids[1]}`;
};

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
  const [activeP2PConversationId, setActiveP2PConversationId] = useState<string | null>(null); // New state for canonical conversation ID

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
    }
  }, [messages]);

  const addSystemMessage = (text: string, _systemMessageType: 'system-info' | 'system-error') => {
    setMessages(prevMessages => [
      ...prevMessages,
      {
        id: `sys-${Date.now()}`,
        conversationId: activeP2PConversationId || currentChatPeer?.peerId || 'system', // Decide which ID to use for system messages
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

  // Update activeP2PConversationId when currentUser or currentChatPeer changes
  useEffect(() => {
    if (currentUser && currentChatPeer) {
      const newConversationId = determineP2PConversationId(currentUser.userId, currentChatPeer.peerId);
      setActiveP2PConversationId(newConversationId);
      console.log(`ChatPage: Set activeP2PConversationId to: ${newConversationId}`);
    } else {
      setActiveP2PConversationId(null); // Clear if no user or peer
    }
  }, [currentUser, currentChatPeer]);

  // Fetch messages when activeP2PConversationId changes
  const fetchMessages = useCallback(async () => {
    if (!activeP2PConversationId || !currentUser) {
        console.log("ChatPage: Skipping fetchMessages. No activeP2PConversationId or currentUser.", "ActiveID:", activeP2PConversationId, "User:", currentUser);
        return;
    }
    console.log(`ChatPage: Fetching messages for canonical conversation ID: ${activeP2PConversationId}`);
    try {
      const fetchedMessages = await getMessagesByConversationIdAPI(activeP2PConversationId);
      // Assuming API returns messages sorted newest-first.
      // Reverse to display oldest-first, so newest appears at the bottom of the chat.
      setMessages(fetchedMessages.slice().reverse());
      markConversationAsReadAPI(activeP2PConversationId).catch(err => console.error("Failed to mark conversation as read for", activeP2PConversationId, err));
    } catch (error) {
      console.error('ChatPage: Error fetching messages for ', activeP2PConversationId, error);
      setChatError('Failed to load messages.');
      // addSystemMessage('Error fetching messages.', 'system-error'); // Consider if system message should use peerId or canonicalId
    }
  }, [activeP2PConversationId, currentUser]);

  useEffect(() => {
    if (activeP2PConversationId) {
      fetchMessages();
      const intervalId = setInterval(fetchMessages, 3000);
      return () => clearInterval(intervalId);
    } else {
      setMessages([]);
    }
  }, [activeP2PConversationId, fetchMessages]);

  const handleSendMessage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    console.log('ChatPage: handleSendMessage triggered.');

    if (currentMessage.trim() === '' || isSending || !currentChatPeer || !currentUser || !activeP2PConversationId) {
      console.warn('ChatPage: Send message validation failed. Conditions:');
      console.warn(`  - currentMessage.trim() === '': ${currentMessage.trim() === ''}`);
      console.warn(`  - isSending: ${isSending}`);
      console.warn(`  - !currentChatPeer: ${!currentChatPeer}`);
      console.warn(`  - !currentUser: ${!currentUser}`);
      console.warn(`  - !activeP2PConversationId: ${!activeP2PConversationId}`);
      if (!currentChatPeer) addSystemMessage('No user selected to chat with.', 'system-error');
      if (!currentUser) console.warn('ChatPage: Send message aborted. No currentUser.');
      if (isSending) console.warn('ChatPage: Send message aborted. Already sending.');
      if (currentMessage.trim() === '') console.warn('ChatPage: Send message aborted. Message is empty.');
      if (!activeP2PConversationId) console.warn('ChatPage: Send message aborted. No activeP2PConversationId.');
      return;
    }

    console.log('ChatPage: Passed initial validation. Proceeding to send.');
    setIsSending(true);
    const textToSend = currentMessage;
    setCurrentMessage('');

    // Double check, though validation above should catch it.
    if (!currentUser || !currentChatPeer || !activeP2PConversationId) {
        console.error("ChatPage: Critical error - currentUser, currentChatPeer, or activeP2PConversationId is null before sending optimistic message.");
        addSystemMessage('Critical error: User, Peer or Conversation context lost.', 'system-error');
        setIsSending(false);
        return;
    }

    const optimisticMessage: Message = {
      id: `temp-${Date.now()}`,
      conversationId: activeP2PConversationId, // Use canonical ID
      senderId: currentUser.userId,
      recipientId: currentChatPeer.peerId, // Recipient ID remains the peer's specific ID
      payload: textToSend,
      type: MessageType.TEXT,
      timestamp: new Date(),
      status: MessageStatus.SENT,
      originalMessageId: replyingToMessage ? replyingToMessage.id : null,
    };
    setMessages(prevMessages => [...prevMessages, optimisticMessage]);

    if (replyingToMessage) {
      setReplyingToMessage(null);
    }

    try {
      const messageDto: SendMessageDTO = {
        conversationId: activeP2PConversationId, // Use canonical ID
        recipientId: currentChatPeer.peerId,    // Recipient ID remains the peer's specific ID
        type: MessageType.TEXT,
        payload: textToSend,
        originalMessageId: optimisticMessage.originalMessageId,
      };
      console.log('ChatPage: Attempting to call sendMessageAPI with DTO:', messageDto);
      const sentMessage = await sendMessageAPI(messageDto);
      console.log('ChatPage: sendMessageAPI successful. Response:', sentMessage);
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
      setMessages(prevMessages =>
        prevMessages.map(msg => (msg.id === optimisticMessage.id ? { ...msg, status: MessageStatus.FAILED } : msg))
      );
    } finally {
      setIsSending(false);
      console.log('ChatPage: handleSendMessage finished.');
    }
  };

  const getSenderDisplayName = (senderId: string): string => {
    if (currentUser && senderId === currentUser.userId) return "You";
    if (currentChatPeer && senderId === currentChatPeer.peerId) return currentChatPeer.username || currentChatPeer.peerId;
    if (senderId === 'system') return "System";
    return senderId; // Fallback to senderId
  };

  const getMessageStyle = (message: Message) => {
    if (message.senderId === 'system') {
      return {
        textAlign: 'center' as const,
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
  };

  const handleConnectionAttempt = (peerId: string) => {
    setConnectionStatus(`Attempting to connect to ${peerId}...`);
    addSystemMessage(`Attempting to connect to ${peerId}...`, 'system-info');
    setCurrentChatPeer(null); // Clear current chat while attempting new connection
    setMessages([]);
  };

  const handleConnectionSuccess = (peer: DiscoveredPeer, message: string) => { // Parameter name reverted to 'message'
    setConnectionStatus(`Connected to ${peer.peerId}. ${message}`);
    addSystemMessage(`Successfully connected to ${peer.peerId}. ${message}`, 'system-info');
    setCurrentChatPeer(peer);
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
          onSelectPeer={handleSelectPeer}
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

            let originalMsgDisplay = null;
            if (msg.originalMessageId) {
              const original = messages.find(m => m.id === msg.originalMessageId);
              if (original) {
                const isOriginalFromCurrentUser = original.senderId === currentUser?.userId;
                originalMsgDisplay = (
                  <div style={{
                    fontSize: '0.8em',
                    padding: '5px 8px',
                    background: isOriginalFromCurrentUser ? 'rgba(220, 248, 198, 0.7)' : 'rgba(225, 225, 225, 0.7)',
                    borderRadius: '5px',
                    marginBottom: '4px',
                    borderLeft: `3px solid ${isOriginalFromCurrentUser ? '#a7d78f' : '#c0c0c0'}`,
                    opacity: 0.9,
                    cursor: 'pointer',
                  }}
                  onClick={() => {
                    const originalMessageElement = document.getElementById(`msg-${original.id}`);
                    if (originalMessageElement) {
                      originalMessageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                      originalMessageElement.style.transition = 'background-color 0.2s ease-out';
                      originalMessageElement.style.backgroundColor = '#fffacd'; // LemonChiffon for highlight
                      setTimeout(() => {
                        originalMessageElement.style.backgroundColor = ''; // Reset background
                      }, 1500);
                    }
                  }}
                  title="Scroll to original message"
                  >
                    <strong>{getSenderDisplayName(original.senderId)}:</strong>
                    <span style={{ marginLeft: '5px', fontStyle: 'italic' }}>
                      {original.payload.length > 60 ? original.payload.substring(0, 57) + '...' : original.payload}
                    </span>
                  </div>
                );
              }
            }

            return (
              <div key={msg.id} id={`msg-${msg.id}`} style={{ marginBottom: '8px', display: 'flex', justifyContent: styles.textAlign === 'right' ? 'flex-end' : (styles.textAlign === 'center' ? 'center' : 'flex-start') }}>
                <div style={{ maxWidth: '70%', display: 'flex', flexDirection: styles.textAlign === 'right' ? 'row-reverse' : 'row', alignItems: 'flex-end' }}>
                  <div style={{
                    order: styles.textAlign === 'right' ? 1 : 0,
                    alignSelf: styles.textAlign === 'right' ? 'flex-end' : 'flex-start',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: styles.textAlign === 'right' ? 'flex-end' : 'flex-start',
                  }}>
                    {originalMsgDisplay}
                    <span style={{
                      background: styles.background,
                      color: styles.color,
                      fontStyle: styles.fontStyle,
                      padding: '8px 12px',
                      borderRadius: '10px',
                      display: 'inline-block',
                      wordBreak: 'break-word',
                      order: styles.textAlign === 'right' ? 1 : 0,
                    }}>
                      <div style={{ fontSize: '0.8em', color: '#555', marginBottom: '2px', textAlign: styles.textAlign === 'right' ? 'right' : 'left'}}>
                        {displayName}
                      </div>
                      {msg.payload}
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
                          order: styles.textAlign === 'right' ? 0 : 1,
                          alignSelf: 'center',
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
            id="chat-message-input"
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
