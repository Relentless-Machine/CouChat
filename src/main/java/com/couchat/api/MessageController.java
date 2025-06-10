// src/main/java/com/couchat/api/MessageController.java
package com.couchat.api;

import com.couchat.api.dto.*;
import com.couchat.security.MessageSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger logger = LoggerFactory.getLogger(MessageController.class);

    @Autowired
    public MessageController(MessageSecurityManager messageSecurityManager) {
        this.messageSecurityManager = messageSecurityManager;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<?> encryptMessage(@RequestBody MessageRequest request) {
        if (request == null || request.plainText() == null || request.plainText().isEmpty()) {
            logger.warn("Encryption request failed: Plain text was null or empty.");
            return ResponseEntity.badRequest().body("Plain text cannot be null or empty.");
        }
        String plainTextPreview = request.plainText().substring(0, Math.min(request.plainText().length(), 20));
        logger.info("Received encryption request for plainText: '{}...'", plainTextPreview);
        try {
            String encryptedText = messageSecurityManager.encryptDirect(request.plainText());
            if (encryptedText == null) {
                logger.error("Encryption resulted in null output for plainText: '{}...'", plainTextPreview);
                return ResponseEntity.internalServerError().body("Encryption resulted in null output.");
            }
            logger.info("Successfully encrypted text. Returning (first 20 chars of encrypted): '{}...'",
                        encryptedText.substring(0, Math.min(encryptedText.length(), 20)));
            return ResponseEntity.ok(new EncryptedMessageResponse(encryptedText));
        } catch (IllegalStateException e) {
            logger.error("Encryption failed due to illegal state for plainText: '{}...'. Error: {}",
                         plainTextPreview, e.getMessage(), e);
            return ResponseEntity.status(500).body("Encryption failed: Key not initialized or invalid state.");
        } catch (Exception e) {
            logger.error("An unexpected error occurred during message encryption for plainText: '{}...'. Error: {}",
                         plainTextPreview, e.getMessage(), e);
            return ResponseEntity.status(500).body("Encryption failed due to an unexpected error.");
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> decryptMessage(@RequestBody DecryptionRequest request) {
        if (request == null || request.encryptedText() == null || request.encryptedText().isEmpty()) {
            logger.warn("Decryption request failed: Encrypted text was null or empty.");
            return ResponseEntity.badRequest().body("Encrypted text cannot be null or empty.");
        }
        String encryptedTextPreview = request.encryptedText().substring(0, Math.min(request.encryptedText().length(), 20));
        logger.info("Received decryption request for encryptedText: '{}...'", encryptedTextPreview);
        try {
            String decryptedText = messageSecurityManager.decryptDirect(request.encryptedText());
            if (decryptedText == null) {
                 logger.error("Decryption resulted in null output for encryptedText: '{}...'", encryptedTextPreview);
                return ResponseEntity.internalServerError().body("Decryption resulted in null output (possibly due to invalid input or key issue).");
            }
            logger.info("Successfully decrypted text (first 20 chars of decrypted): '{}...'",
                        decryptedText.substring(0, Math.min(decryptedText.length(), 20)));
            return ResponseEntity.ok(new DecryptedMessageResponse(decryptedText));
        } catch (IllegalStateException e) {
            logger.error("Decryption failed due to illegal state for encryptedText: '{}...'. Error: {}",
                         encryptedTextPreview, e.getMessage(), e);
            return ResponseEntity.status(500).body("Decryption failed: Key not initialized or invalid state.");
        } catch (Exception e) {
            // Log as WARN for common decryption issues like bad padding/key, ERROR for others.
            logger.warn("Decryption failed for encryptedText: '{}...', likely due to invalid encrypted text or key mismatch. Error: {}",
                         encryptedTextPreview, e.getMessage(), e);
            return ResponseEntity.status(400).body("Decryption failed: Invalid encrypted text or key mismatch.");
        }
    }
}
