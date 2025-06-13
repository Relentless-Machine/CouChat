package com.couchat.p2p;

import com.couchat.messaging.MessageService;
import com.couchat.messaging.model.Message;
import com.couchat.security.EncryptionService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class P2PConnectionTest {

    private static final Logger logger = LoggerFactory.getLogger(P2PConnectionTest.class);

    @Mock
    private Socket mockSocket;
    @Mock
    private P2PConnectionManager mockConnectionManager;
    @Mock
    private EncryptionService mockEncryptionService;
    @Mock
    private MessageService mockMessageService;

    private P2PConnection p2pConnection;
    private InputStream mockInputStream;
    private OutputStream mockOutputStream;

    private static final String LOCAL_PEER_ID = "localTestPeer";
    private static final String REMOTE_PEER_ID = "remoteTestPeer";
    private SecretKey testSessionKey;

    // Helper method to determine conversation ID for tests
    private String determineConversationId(String userId1, String userId2) {
        if (userId1.compareTo(userId2) < 0) {
            return userId1 + "_" + userId2;
        } else {
            return userId2 + "_" + userId1;
        }
    }

    @BeforeEach
    void setUp() throws IOException {
        // Generate a dummy AES key for testing
        byte[] keyBytes = new byte[32]; // 256-bit key
        for (int i = 0; i < keyBytes.length; i++) keyBytes[i] = (byte) i;
        testSessionKey = new SecretKeySpec(keyBytes, "AES");

        // Mock InputStream and OutputStream for the socket
        // Using ByteArrayInputStream/OutputStream to simulate network I/O
        mockInputStream = new ByteArrayInputStream(new byte[0]); // Start with empty input stream
        mockOutputStream = new ByteArrayOutputStream(); // Capture output

        when(mockSocket.getInputStream()).thenReturn(mockInputStream);
        when(mockSocket.getOutputStream()).thenReturn(mockOutputStream);
        // Use lenient stubbing for general socket state mocks in setUp
        lenient().when(mockSocket.isClosed()).thenReturn(false); // Assume socket is open initially
        lenient().when(mockSocket.isConnected()).thenReturn(true); // Assume socket is connected initially

        p2pConnection = new P2PConnection(
                LOCAL_PEER_ID,
                REMOTE_PEER_ID,
                mockSocket,
                mockConnectionManager,
                mockEncryptionService,
                mockMessageService
        );
        logger.info("P2PConnectionTest setup complete.");
    }

    @AfterEach
    void tearDown() throws IOException {
        if (p2pConnection != null) {
            p2pConnection.close(); // Ensure connection is closed, also tests close method implicitly
        }
        // Verify that the manager is notified about connection removal upon close
        // This check is here because close() is called in tearDown
        if (p2pConnection != null && mockConnectionManager != null) { // Check if p2pConnection was successfully created
             verify(mockConnectionManager, atLeastOnce()).removeConnection(REMOTE_PEER_ID);
        }
        logger.info("P2PConnectionTest teardown complete.");
    }

    @Test
    void testSendMessage_HandshakeNotComplete() {
        logger.info("Testing sendMessage when handshake is not complete...");
        Message testMessage = new Message(determineConversationId(LOCAL_PEER_ID, REMOTE_PEER_ID), Message.MessageType.TEXT, LOCAL_PEER_ID, REMOTE_PEER_ID, "Hello World");

        // Simulate messageService.prepareOutgoingMessage if it's called even when handshake is not complete
        // For this test, we assume P2PConnection checks handshake status *before* calling prepareOutgoingMessage.
        // If prepareOutgoingMessage was called, we'd mock it:
        // when(mockMessageService.prepareOutgoingMessage(any(Message.class))).thenReturn("{\\"content\\":\\"Hello World\\"}");

        p2pConnection.sendMessage(testMessage);

        // Verify no encryption or send attempt was made
        verify(mockMessageService, never()).prepareOutgoingMessage(any(Message.class));
        verify(mockEncryptionService, never()).encryptWithAesKey(any(), any());
        assertEquals(0, ((ByteArrayOutputStream) mockOutputStream).size(), "OutputStream should be empty if handshake is not complete.");
        logger.info("sendMessage_HandshakeNotComplete test passed.");
    }

    @Test
    void testSendMessage_SessionKeyNotAvailable() {
        logger.info("Testing sendMessage when session key is not available (but handshake marked complete)...");
        p2pConnection.setHandshakeComplete(); // Mark handshake as complete
        Message testMessage = new Message(determineConversationId(LOCAL_PEER_ID, REMOTE_PEER_ID), Message.MessageType.TEXT, LOCAL_PEER_ID, REMOTE_PEER_ID, "Hello World");

        // As above, assume P2PConnection checks session key status *before* calling prepareOutgoingMessage.
        // when(mockMessageService.prepareOutgoingMessage(any(Message.class))).thenReturn("{\\"content\\":\\"Hello World\\"}");

        p2pConnection.sendMessage(testMessage);

        verify(mockMessageService, never()).prepareOutgoingMessage(any(Message.class));
        verify(mockEncryptionService, never()).encryptWithAesKey(any(), any());
        assertEquals(0, ((ByteArrayOutputStream) mockOutputStream).size(), "OutputStream should be empty if session key is null.");
        logger.info("sendMessage_SessionKeyNotAvailable test passed.");
    }

    @Test
    void testSendMessage_Successful() throws IOException {
        logger.info("Testing successful sendMessage...");
        p2pConnection.setSessionAesKey(testSessionKey);
        p2pConnection.setHandshakeComplete();

        String messageContent = "This is a test message.";
        Message testMessage = new Message(determineConversationId(LOCAL_PEER_ID, REMOTE_PEER_ID), Message.MessageType.TEXT, LOCAL_PEER_ID, REMOTE_PEER_ID, messageContent);

        // Simplified and direct JSON string for the test
        // ObjectMapper in MessageService will handle actual serialization.
        // For mocking prepareOutgoingMessage, we need a plausible JSON string.
        // Let's assume MessageService.prepareOutgoingMessage correctly serializes it.
        // The exact content of serializedMessageJson will depend on ObjectMapper configuration in MessageService.
        // For the purpose of this test, we can use a simplified representation if MessageService is mocked.
        // However, it's better to make it somewhat realistic if possible, or ensure the mock is robust.
        // String serializedMessageJson = "{\"id\":\"" + testMessage.getMessageId() + "\",\"type\":\"TEXT\",\"senderId\":\"" + LOCAL_PEER_ID + "\",\"recipientId\":\"" + REMOTE_PEER_ID + "\",\"timestamp\":\"" + testMessage.getTimestamp().toString() + "\",\"payload\":\"This is a test message.\"}";
        // To avoid issues with timestamp exact match, let's use a more generic payload string for mocking, as MessageService handles the actual serialization.
        String serializedMessageJson = "{\"payload\":\"This is a test message.\"}"; // Simplified for mocking

        byte[] serializedMessageBytes = serializedMessageJson.getBytes(StandardCharsets.UTF_8);
        String encryptedMessageB64 = Base64.getEncoder().encodeToString("encrypted_content".getBytes(StandardCharsets.UTF_8));

        when(mockMessageService.prepareOutgoingMessage(eq(testMessage))).thenReturn(serializedMessageJson);
        when(mockEncryptionService.encryptWithAesKey(eq(serializedMessageBytes), eq(testSessionKey))).thenReturn(encryptedMessageB64);

        p2pConnection.sendMessage(testMessage);

        verify(mockMessageService, times(1)).prepareOutgoingMessage(testMessage);
        verify(mockEncryptionService, times(1)).encryptWithAesKey(serializedMessageBytes, testSessionKey);
        assertEquals(encryptedMessageB64, ((ByteArrayOutputStream) mockOutputStream).toString(StandardCharsets.UTF_8),
                "OutputStream should contain the Base64 encoded encrypted message.");
        logger.info("sendMessage_Successful test passed.");
    }

    @Test
    void testSendMessage_SerializationFails() throws IOException {
        logger.info("Testing sendMessage when message serialization fails...");
        p2pConnection.setSessionAesKey(testSessionKey);
        p2pConnection.setHandshakeComplete();

        Message testMessage = new Message(determineConversationId(LOCAL_PEER_ID, REMOTE_PEER_ID), Message.MessageType.TEXT, LOCAL_PEER_ID, REMOTE_PEER_ID, "Another test message.");

        when(mockMessageService.prepareOutgoingMessage(eq(testMessage))).thenReturn(null); // Simulate serialization failure

        p2pConnection.sendMessage(testMessage);

        verify(mockMessageService, times(1)).prepareOutgoingMessage(testMessage);
        verify(mockEncryptionService, never()).encryptWithAesKey(any(), any()); // Encryption should not be attempted
        assertEquals(0, ((ByteArrayOutputStream) mockOutputStream).size(), "OutputStream should be empty if serialization fails.");
        logger.info("sendMessage_SerializationFails test passed.");
    }


    @Test
    void testSendMessage_EncryptionFails() throws IOException {
        logger.info("Testing sendMessage when encryption fails...");
        p2pConnection.setSessionAesKey(testSessionKey);
        p2pConnection.setHandshakeComplete();

        Message testMessage = new Message(determineConversationId(LOCAL_PEER_ID, REMOTE_PEER_ID), Message.MessageType.TEXT, LOCAL_PEER_ID, REMOTE_PEER_ID, "Another test message.");
        // Simplified JSON string
        String serializedMessageJson = "{\"payload\":\"Another test message.\"}"; // Simplified for mocking
        byte[] serializedMessageBytes = serializedMessageJson.getBytes(StandardCharsets.UTF_8);

        when(mockMessageService.prepareOutgoingMessage(eq(testMessage))).thenReturn(serializedMessageJson);
        when(mockEncryptionService.encryptWithAesKey(eq(serializedMessageBytes), eq(testSessionKey))).thenReturn(null); // Simulate encryption failure

        p2pConnection.sendMessage(testMessage);

        verify(mockMessageService, times(1)).prepareOutgoingMessage(testMessage);
        verify(mockEncryptionService, times(1)).encryptWithAesKey(serializedMessageBytes, testSessionKey);
        assertEquals(0, ((ByteArrayOutputStream) mockOutputStream).size(), "OutputStream should be empty if encryption fails.");
        logger.info("sendMessage_EncryptionFails test passed.");
    }

    @Test
    void testRun_ReceivesAndDecryptsMessage_Successful() throws Exception {
        logger.info("Testing run method for successful message reception and decryption...");
        String decryptedMessageJson = "{\"content\":\"Decrypted test data\"}"; // Assuming this is the expected JSON structure
        String encryptedMessageB64 = Base64.getEncoder().encodeToString("encrypted_test_data_for_decryption".getBytes(StandardCharsets.UTF_8)); // Use a distinct string

        // Simulate incoming data
        mockInputStream = new ByteArrayInputStream(encryptedMessageB64.getBytes(StandardCharsets.UTF_8));
        when(mockSocket.getInputStream()).thenReturn(mockInputStream); // Update mock to use new stream
        // Re-initialize p2pConnection with the new mockInputStream if constructor is the only place it's set
        // Or, if P2PConnection could re-fetch it, that would be fine. For this test, let's assume it's fetched once.
        // To make it simpler, we'll re-create p2pConnection for this specific input stream scenario.
        // This is a common pattern if the object under test caches such resources from constructor.
        p2pConnection = new P2PConnection(LOCAL_PEER_ID, REMOTE_PEER_ID, mockSocket, mockConnectionManager, mockEncryptionService, mockMessageService);

        p2pConnection.setSessionAesKey(testSessionKey);
        p2pConnection.setHandshakeComplete();

        when(mockEncryptionService.decryptWithAesKey(eq(encryptedMessageB64), eq(testSessionKey)))
                .thenReturn(decryptedMessageJson.getBytes(StandardCharsets.UTF_8));

        Thread listenerThread = new Thread(p2pConnection);
        listenerThread.start();

        // Allow some time for the listener thread to process the message
        Thread.sleep(200); // Adjust as needed, can be flaky. Consider CountDownLatch for robust async testing.

        p2pConnection.close(); // Stop the listener thread
        listenerThread.join(500); // Wait for thread to finish

        verify(mockEncryptionService, times(1)).decryptWithAesKey(encryptedMessageB64, testSessionKey);
        verify(mockMessageService, times(1)).processIncomingMessage(REMOTE_PEER_ID, decryptedMessageJson);
        logger.info("run_ReceivesAndDecryptsMessage_Successful test passed.");
    }

    @Test
    void testRun_IgnoresDataBeforeHandshakeComplete() throws Exception {
        logger.info("Testing run method ignores data before handshake is complete...");
        String incomingData = "some_data_before_handshake";
        mockInputStream = new ByteArrayInputStream(incomingData.getBytes(StandardCharsets.UTF_8));
        when(mockSocket.getInputStream()).thenReturn(mockInputStream);
        p2pConnection = new P2PConnection(LOCAL_PEER_ID, REMOTE_PEER_ID, mockSocket, mockConnectionManager, mockEncryptionService, mockMessageService);

        // Handshake is NOT complete
        // p2pConnection.setSessionAesKey(testSessionKey); // Key not set either

        Thread listenerThread = new Thread(p2pConnection);
        listenerThread.start();
        Thread.sleep(100);
        p2pConnection.close();
        listenerThread.join(500);

        verify(mockEncryptionService, never()).decryptWithAesKey(anyString(), any(SecretKey.class));
        verify(mockMessageService, never()).processIncomingMessage(anyString(), anyString());
        logger.info("run_IgnoresDataBeforeHandshakeComplete test passed.");
    }

    @Test
    void testRun_HandlesDecryptionFailure() throws Exception {
        logger.info("Testing run method handles decryption failure...");
        String encryptedMessageB64 = "corrupted_or_invalid_encrypted_data";
        mockInputStream = new ByteArrayInputStream(encryptedMessageB64.getBytes(StandardCharsets.UTF_8));
        when(mockSocket.getInputStream()).thenReturn(mockInputStream);
        p2pConnection = new P2PConnection(LOCAL_PEER_ID, REMOTE_PEER_ID, mockSocket, mockConnectionManager, mockEncryptionService, mockMessageService);

        p2pConnection.setSessionAesKey(testSessionKey);
        p2pConnection.setHandshakeComplete();

        when(mockEncryptionService.decryptWithAesKey(eq(encryptedMessageB64), eq(testSessionKey))).thenReturn(null); // Simulate decryption failure

        Thread listenerThread = new Thread(p2pConnection);
        listenerThread.start();
        Thread.sleep(100);
        p2pConnection.close();
        listenerThread.join(500);

        verify(mockEncryptionService, times(1)).decryptWithAesKey(encryptedMessageB64, testSessionKey);
        verify(mockMessageService, never()).processIncomingMessage(anyString(), anyString()); // Message service should not be called
        logger.info("run_HandlesDecryptionFailure test passed.");
    }

    @Test
    void testClose_ClosesSocketAndNotifiesManager() throws IOException {
        logger.info("Testing close method...");
        // p2pConnection is created in setUp
        p2pConnection.close();

        verify(mockSocket, times(1)).close();
        verify(mockConnectionManager, times(1)).removeConnection(REMOTE_PEER_ID);
        assertFalse(p2pConnection.isActive(), "Connection should be inactive after close.");
        logger.info("close_ClosesSocketAndNotifiesManager test passed.");
    }

    @Test
    void testIsActive() {
        logger.info("Testing isActive method...");
        assertTrue(p2pConnection.isActive(), "Connection should be active initially (mocked socket is open).");

        when(mockSocket.isClosed()).thenReturn(true);
        assertFalse(p2pConnection.isActive(), "Connection should be inactive if socket is closed.");
        logger.info("isActive test passed.");
    }
}
