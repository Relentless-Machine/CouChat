// filepath: F:/Git/CouChat/src/test/java/com/couchat/web/controller/MessageControllerTest.java
package com.couchat.web.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.messaging.model.Message;
import com.couchat.messaging.service.MessageService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import org.springframework.security.test.context.support.WithMockUser;

@WebMvcTest(MessageController.class)
public class MessageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private MessageService messageService;

    @MockBean
    private PasskeyAuthService passkeyAuthService;

    private String mockUserId;
    private String mockConversationId;
    private Message mockMessage;

    @BeforeEach
    void setUp() {
        mockUserId = "testUser123";
        mockConversationId = "p2p_" + mockUserId + "_testRecipient456"; // Assuming sorted or a fixed convention for testing

        when(passkeyAuthService.getLocalUserId()).thenReturn(mockUserId);

        mockMessage = new Message(
                UUID.randomUUID().toString(),
                mockConversationId,
                Message.MessageType.TEXT,
                mockUserId,
                "testRecipient456",
                "Hello from test",
                Instant.now(),
                null,
                Message.MessageStatus.SENT,
                null
        );
    }

    @Test
    @WithMockUser(username="testUser123") // Simulate authenticated user
    void sendMessage_whenUserAuthenticatedAndValidMessage_shouldReturnCreated() throws Exception {
        // Ensure passkeyAuthService is properly mocked for this "authenticated" scenario
        when(passkeyAuthService.getLocalUserId()).thenReturn(mockUserId);

        Message clientDto = new Message(
                mockConversationId,
                Message.MessageType.TEXT,
                "dummySenderInDto", // Provide a dummy non-null value, controller will use authenticated user's ID
                "testRecipient456",
                "Hello from test"
        );

        // Ensure the messageService.sendMessage is mocked to behave as expected
        // The message passed to messageService.sendMessage will have senderId set by the controller
        when(messageService.sendMessage(any(Message.class))).thenAnswer(invocation -> {
            Message msgToSave = invocation.getArgument(0);
            // Simulate saving by returning a message that includes the senderId
            return new Message(
                    UUID.randomUUID().toString(),
                    msgToSave.getConversationId(),
                    msgToSave.getType(),
                    mockUserId, // Crucially, this should be the authenticated user's ID
                    msgToSave.getRecipientId(),
                    msgToSave.getPayload(),
                    Instant.now(),
                    msgToSave.getOriginalMessageId(),
                    Message.MessageStatus.SENT, // Simulate that service has processed it to SENT
                    null
            );
        });

        mockMvc.perform(post("/api/messages")
                .with(csrf()) // Added CSRF token
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(clientDto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.senderId", is(mockUserId))) // Verify senderId in response
                .andExpect(jsonPath("$.payload", is("Hello from test")))
                .andExpect(jsonPath("$.conversationId", is(mockConversationId)));
    }

    @Test
    // No @WithMockUser here, as this test is for unauthenticated users
    void sendMessage_whenUserNotAuthenticated_shouldReturnUnauthorized() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(null); // Simulate not authenticated

        Message clientDto = new Message(
                mockConversationId,
                Message.MessageType.TEXT,
                "dummySenderInDto", // Provide a dummy non-null value to avoid NPE during DTO creation
                "testRecipient456",
                "Test"
        );

        mockMvc.perform(post("/api/messages")
                .with(csrf()) // Added CSRF token
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(clientDto)))
                .andExpect(status().isUnauthorized()); // Controller should return 401 before trying to create Message
    }

    @Test
    @WithMockUser(username="testUser123") // Simulate authenticated user
    void getMessagesByConversation_whenAuthenticatedAndConversationExists_shouldReturnMessages() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(mockUserId); // Ensure authenticated
        List<Message> messages = Collections.singletonList(mockMessage);
        when(messageService.getMessagesByConversation(mockConversationId, 50, 0)).thenReturn(messages);

        mockMvc.perform(get("/api/messages/conversation/{conversationId}", mockConversationId)
                .param("limit", "50")
                .param("offset", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].messageId", is(mockMessage.getMessageId())));
    }

    @Test
    void getMessagesByConversation_whenNotAuthenticated_shouldReturnUnauthorized() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(null); // Ensure not authenticated

        mockMvc.perform(get("/api/messages/conversation/{conversationId}", mockConversationId))
                .andExpect(status().isUnauthorized());
    }


    @Test
    @WithMockUser(username="testUser123") // Simulate authenticated user
    void markConversationAsRead_whenAuthenticated_shouldReturnOk() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(mockUserId); // Ensure authenticated
        doNothing().when(messageService).markMessagesAsRead(mockConversationId, mockUserId);

        mockMvc.perform(post("/api/messages/conversation/{conversationId}/read", mockConversationId)
                .with(csrf())) // Added CSRF token
                .andExpect(status().isOk());
    }

    @Test
    void markConversationAsRead_whenNotAuthenticated_shouldReturnUnauthorized() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(null); // Ensure not authenticated

        mockMvc.perform(post("/api/messages/conversation/{conversationId}/read", mockConversationId)
                .with(csrf())) // Added CSRF token
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username="testUser123") // Simulate authenticated user
    void getMessageById_whenAuthenticatedAndMessageExists_shouldReturnMessage() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(mockUserId); // Ensure authenticated
        when(messageService.getMessageById(mockMessage.getMessageId())).thenReturn(Optional.of(mockMessage));

        mockMvc.perform(get("/api/messages/{messageId}", mockMessage.getMessageId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.messageId", is(mockMessage.getMessageId())));
    }

    @Test
    @WithMockUser(username="testUser123") // Simulate authenticated user
    void getMessageById_whenAuthenticatedAndMessageNotFound_shouldReturnNotFound() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(mockUserId); // Ensure authenticated
        String nonExistentMessageId = UUID.randomUUID().toString();
        when(messageService.getMessageById(nonExistentMessageId)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/messages/{messageId}", nonExistentMessageId))
                .andExpect(status().isNotFound());
    }

    @Test
    void getMessageById_whenNotAuthenticated_shouldReturnUnauthorized() throws Exception {
        when(passkeyAuthService.getLocalUserId()).thenReturn(null); // Ensure not authenticated

        mockMvc.perform(get("/api/messages/{messageId}", mockMessage.getMessageId()))
                .andExpect(status().isUnauthorized());
    }
}
