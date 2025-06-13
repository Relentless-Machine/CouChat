package com.couchat.transfer.controller;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.transfer.model.FileTransfer;
import com.couchat.transfer.service.FileTransferService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
     * Placeholder for initiating a file upload.
     * In a real app, this would handle receiving file metadata, creating a FileTransfer record,
     * and then subsequent requests would handle chunks.
     *
     * @param file The multipart file (not fully handled in this stub).
     * @param messageId The ID of the FILE_INFO message this transfer relates to.
     * @return A FileTransfer record.
     */
    @PostMapping("/upload")
    public ResponseEntity<FileTransfer> initiateFileUpload(
            @RequestParam("file") MultipartFile file, // Spring MVC for file uploads
            @RequestParam("messageId") String messageId,
            @RequestParam("fileName") String fileName,
            @RequestParam("fileSize") long fileSize,
            @RequestParam("mimeType") String mimeType) {
        String currentUserId = passkeyAuthService.getLocalUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        logger.info("POST /api/files/upload - initiateFileUpload called by user: {} for messageId: {}", currentUserId, messageId);
        logger.info("File details: name={}, size={}, type={}", fileName, fileSize, mimeType);

        if (file.isEmpty()) {
            logger.warn("File upload attempt with empty file.");
            return ResponseEntity.badRequest().build();
        }

        try {
            // 1. Create FileTransfer object
            FileTransfer newFileTransfer = new FileTransfer(messageId, fileName, fileSize, mimeType);
            // In a real scenario, you might save the file to a temporary location first
            // and then update the localPath in FileTransfer object.
            // String tempPath = saveFileTemporarily(file, newFileTransfer.getFileId());
            // newFileTransfer.setLocalPath(tempPath);

            FileTransfer initiatedTransfer = fileTransferService.initiateFileTransfer(newFileTransfer);

            // TODO: The actual file bytes from MultipartFile need to be streamed/processed.
            // This endpoint is just for creating the record.
            // The client would then send a FILE_INFO message, and upon acceptance, start sending chunks.

            logger.info("File transfer record created: {}", initiatedTransfer.getFileId());
            return ResponseEntity.status(HttpStatus.CREATED).body(initiatedTransfer);
        } catch (Exception e) {
            logger.error("Error initiating file upload for messageId {}: {}", messageId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
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
        boolean success = fileTransferService.updateTransferStatus(fileId, FileTransfer.FileTransferStatus.ACCEPTED);
        if (success) {
            // TODO: Notify sender to start sending chunks.
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build(); // Or not found, or bad request
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
        boolean success = fileTransferService.updateTransferStatus(fileId, FileTransfer.FileTransferStatus.REJECTED);
         if (success) {
            // TODO: Notify sender about rejection.
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    // TODO: Add endpoints for actual chunk upload/download if using HTTP for that (not typical for P2P focus)
    // TODO: Add endpoint for cancelling a transfer

}

