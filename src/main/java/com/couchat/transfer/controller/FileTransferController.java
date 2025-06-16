package com.couchat.transfer.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.transfer.model.FileTransfer;
import com.couchat.transfer.FileTransferService; // Corrected import
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.Optional;

/**
 * REST controller for file transfer operations (STUB).
 * Actual file upload/download will require more complex handling.
 */
@RestController
@RequestMapping("/api/files")
public class FileTransferController {

    private static final Logger logger = LoggerFactory.getLogger(FileTransferController.class);
    private final FileTransferService fileTransferService;
    private final PasskeyAuthService passkeyAuthService;

    @Autowired
    public FileTransferController(FileTransferService fileTransferService, PasskeyAuthService passkeyAuthService) {
        this.fileTransferService = fileTransferService;
        this.passkeyAuthService = passkeyAuthService;
    }

    /**
     * Initiates a P2P file transfer request from the current user to a recipient.
     * The actual file data is transferred directly via P2P, not through this HTTP request.
     *
     * @param recipientId The ID of the user to send the file to.
     * @param localFilePath The absolute path of the file on the sender's local system.
     * @return A ResponseEntity containing the fileId if successful, or an error status.
     */
    @PostMapping("/request-transfer")
    public ResponseEntity<Map<String, String>> requestP2PFileTransfer(
            @RequestParam("recipientId") String recipientId,
            @RequestParam("localFilePath") String localFilePath) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        logger.info("POST /api/files/request-transfer - User {} requesting to send file '{}' to recipient {}",
                currentUserId, localFilePath, recipientId);

        if (recipientId == null || recipientId.isEmpty() || localFilePath == null || localFilePath.isEmpty()) {
            logger.warn("Recipient ID or local file path is missing.");
            return ResponseEntity.badRequest().body(Map.of("error", "Recipient ID and local file path are required."));
        }

        try {
            String fileId = fileTransferService.initiateFileTransfer(recipientId, localFilePath);

            if (fileId != null) {
                logger.info("P2P File transfer initiated. File ID: {}", fileId);
                return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("fileId", fileId, "status", "Transfer initiated, awaiting recipient acceptance."));
            } else {
                logger.error("Failed to initiate P2P file transfer from user {} to {}. File: {}", currentUserId, recipientId, localFilePath);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Failed to initiate P2P file transfer."));
            }
        } catch (Exception e) {
            logger.error("Error during P2P file transfer initiation for user {} to {}: {}", currentUserId, recipientId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal server error: " + e.getMessage()));
        }
    }

    /**
     * Gets file transfer status by its ID.
     *
     * @param fileId The ID of the file transfer.
     * @return FileTransfer details.
     */
    @GetMapping("/{fileId}/status")
    public ResponseEntity<FileTransfer> getFileTransferStatus(@PathVariable String fileId) {
        logger.info("GET /api/files/{}/status - getFileTransferStatus called", fileId);
        // TODO: Add permission check
        Optional<FileTransfer> ft = fileTransferService.getFileTransferById(fileId);
        return ft.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Placeholder for client to accept a file transfer.
     * @param fileId The ID of the file transfer to accept.
     * @return ResponseEntity indicating success.
     */
    @PostMapping("/{fileId}/accept")
    public ResponseEntity<Void> acceptFileTransfer(@PathVariable String fileId) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("POST /api/files/{}/accept - called by user {}", fileId, currentUserId);

        // TODO: Validate that currentUserId is the intended recipient of this file transfer.
        // This might involve checking the IncomingFileTransfer object in FileTransferService.

        boolean success = fileTransferService.acceptIncomingTransfer(fileId);
        if (success) {
            logger.info("File transfer {} accepted by user {}", fileId, currentUserId);
            return ResponseEntity.ok().build();
        } else {
            logger.warn("Failed to accept file transfer {} for user {}", fileId, currentUserId);
            // Consider returning more specific error (e.g., NOT_FOUND if transfer doesn't exist, or FORBIDDEN if not recipient)
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Placeholder for client to reject a file transfer.
     * @param fileId The ID of the file transfer to reject.
     * @return ResponseEntity indicating success.
     */
    @PostMapping("/{fileId}/reject")
    public ResponseEntity<Void> rejectFileTransfer(@PathVariable String fileId) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        logger.info("POST /api/files/{}/reject - called by user {}", fileId, currentUserId);

        // TODO: Validate that currentUserId is the intended recipient.

        boolean success = fileTransferService.rejectIncomingTransfer(fileId);
        if (success) {
            logger.info("File transfer {} rejected by user {}", fileId, currentUserId);
            return ResponseEntity.ok().build();
        } else {
            logger.warn("Failed to reject file transfer {} for user {}", fileId, currentUserId);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // TODO: Add endpoints for actual chunk upload/download if using HTTP for that (not typical for P2P focus)
    // TODO: Add endpoint for cancelling a transfer

}
