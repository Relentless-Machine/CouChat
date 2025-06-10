// src/main/java/com/couchat/api/MessageController.java
package com.couchat.api;

import com.couchat.api.dto.*;
import com.couchat.security.MessageSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private final MessageSecurityManager messageSecurityManager;

    @Autowired
    public MessageController(MessageSecurityManager messageSecurityManager) {
        this.messageSecurityManager = messageSecurityManager;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<?> encryptMessage(@RequestBody MessageRequest request) {
        if (request == null || request.plainText() == null || request.plainText().isEmpty()) {
            return ResponseEntity.badRequest().body("Plain text cannot be null or empty.");
        }
        try {
            String encryptedText = messageSecurityManager.encryptDirect(request.plainText());
            if (encryptedText == null) {
                return ResponseEntity.internalServerError().body("Encryption resulted in null output.");
            }
            return ResponseEntity.ok(new EncryptedMessageResponse(encryptedText));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(500).body("Encryption failed: Key not initialized or invalid state.");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Encryption failed due to an unexpected error.");
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> decryptMessage(@RequestBody DecryptionRequest request) {
        if (request == null || request.encryptedText() == null || request.encryptedText().isEmpty()) {
            return ResponseEntity.badRequest().body("Encrypted text cannot be null or empty.");
        }
        try {
            String decryptedText = messageSecurityManager.decryptDirect(request.encryptedText());
            if (decryptedText == null) {
                return ResponseEntity.internalServerError().body("Decryption resulted in null output (possibly due to invalid input or key issue).");
            }
            return ResponseEntity.ok(new DecryptedMessageResponse(decryptedText));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(500).body("Decryption failed: Key not initialized or invalid state.");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Decryption failed: Invalid encrypted text or key mismatch.");
        }
    }
}
