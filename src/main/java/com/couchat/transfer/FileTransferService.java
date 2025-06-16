package com.couchat.transfer;

import com.couchat.auth.PasskeyAuthService;
import com.couchat.messaging.service.MessageService;
import com.couchat.messaging.model.FileChunk;
import com.couchat.messaging.model.FileInfo;
import com.couchat.messaging.model.Message; // Ensure this is the correct Message class
import com.couchat.p2p.P2PConnectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.context.annotation.Lazy; // Import @Lazy

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant; // Added for model construction
import java.util.Map;
import java.util.Optional; // Added
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Service responsible for managing file transfers, both outgoing and incoming.
 */
@Service
public class FileTransferService {

    private static final Logger logger = LoggerFactory.getLogger(FileTransferService.class);
    private static final int CHUNK_SIZE_BYTES = 1024 * 64; // 64KB chunks
    private static final String INCOMING_FILES_DIR = "couchat_incoming_files";


    private final MessageService messageService;
    private final P2PConnectionManager p2pConnectionManager;
    private final PasskeyAuthService passkeyAuthService;
    private final ExecutorService fileTransferExecutor = Executors.newFixedThreadPool(5); // Thread pool for handling chunk sending

    // Maps to keep track of active transfers
    private final Map<String, OutgoingFileTransfer> outgoingTransfers = new ConcurrentHashMap<>();
    private final Map<String, IncomingFileTransfer> incomingTransfers = new ConcurrentHashMap<>();
    private final Path incomingFilesPath; // Added for storing incoming files path

    /**
     * Constructs a FileTransferService.
     *
     * @param messageService       Service for creating messages.
     * @param p2pConnectionManager Manager for P2P connections.
     * @param passkeyAuthService   Service for retrieving local user authentication details.
     */
    @Autowired
    public FileTransferService(MessageService messageService,
                               @Lazy P2PConnectionManager p2pConnectionManager, // Added @Lazy
                               PasskeyAuthService passkeyAuthService) {
        this.messageService = messageService;
        this.p2pConnectionManager = p2pConnectionManager;
        this.passkeyAuthService = passkeyAuthService;

        // Initialize and create the directory for incoming files
        String userHome = System.getProperty("user.home");
        this.incomingFilesPath = Paths.get(userHome, INCOMING_FILES_DIR).toAbsolutePath(); // Ensure absolute path
        try {
            if (!Files.exists(this.incomingFilesPath)) {
                Files.createDirectories(this.incomingFilesPath);
                logger.info("Created directory for incoming files: {}", this.incomingFilesPath);
            } else {
                logger.info("Directory for incoming files already exists: {}", this.incomingFilesPath);
            }
        } catch (IOException e) {
            logger.error("Failed to create directory for incoming files: {}. Incoming file transfers may fail.", this.incomingFilesPath, e);
            // Consider re-throwing or setting a service-unavailable flag if this is critical
        }
    }

    /**
     * Initiates a file transfer to a specified recipient.
     * This involves sending a FILE_INFO message to the recipient.
     * The transfer will only start sending chunks after the recipient accepts.
     *
     * @param recipientId The ID of the peer to send the file to.
     * @param filePath    The absolute path to the local file to be sent.
     * @return The unique file ID for this transfer, or null if initiation fails.
     */
    public String initiateFileTransfer(String recipientId, String filePath) {
        if (!passkeyAuthService.isAuthenticated()) {
            logger.warn("Cannot initiate file transfer: User not authenticated.");
            return null;
        }
        String localUserId = passkeyAuthService.getLocalUserId(); // Corrected
        if (localUserId == null) {
            logger.warn("Cannot initiate file transfer: Local user ID is null.");
            return null;
        }

        File file = new File(filePath);
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            logger.error("Cannot initiate file transfer: File does not exist, is not a file, or cannot be read: {}", filePath);
            return null;
        }

        String fileId = UUID.randomUUID().toString();
        long fileSize = file.length();
        String fileName = file.getName();
        String fileType = null;
        try {
            fileType = Files.probeContentType(file.toPath());
        } catch (IOException e) {
            logger.warn("Could not determine MIME type for file: {}", fileName, e);
        }

        int totalChunks = (int) Math.ceil((double) fileSize / CHUNK_SIZE_BYTES);
        if (fileSize == 0) { // Handle zero-byte files
            totalChunks = 1; // Send one empty chunk
        }

        FileInfo fileInfo = new FileInfo(fileId, fileName, fileSize, fileType, totalChunks);
        OutgoingFileTransfer transfer = new OutgoingFileTransfer(fileId, filePath, recipientId, fileInfo);
        transfer.setStatus(FileTransferStatus.AWAITING_ACCEPTANCE); // Set status to AWAITING_ACCEPTANCE
        outgoingTransfers.put(fileId, transfer);

        Message fileInfoMessage = messageService.createFileInfoMessage(localUserId, recipientId, fileInfo); // Corrected
        p2pConnectionManager.sendMessage(recipientId, fileInfoMessage);

        logger.info("Initiated file transfer, awaiting acceptance. File ID: {}, Name: {}, Recipient: {}. FILE_INFO message sent.",
                    fileId, fileName, recipientId);

        // Removed automatic call to startSendingChunks(fileId);
        // Chunks will be sent after receiving FILE_TRANSFER_ACCEPTED message.

        return fileId;
    }

    /**
     * Handles the FILE_TRANSFER_ACCEPTED message from the recipient.
     *
     * @param fileId The ID of the accepted file transfer.
     * @param senderOfAcceptance The peer ID of the recipient who accepted the transfer.
     */
    public void handleFileTransferAccepted(String fileId, String senderOfAcceptance) {
        OutgoingFileTransfer transfer = outgoingTransfers.get(fileId);
        if (transfer == null) {
            logger.warn("Received FILE_TRANSFER_ACCEPTED for unknown file ID: {} from {}", fileId, senderOfAcceptance);
            return;
        }

        if (!transfer.getRecipientId().equals(senderOfAcceptance)) {
            logger.warn("Received FILE_TRANSFER_ACCEPTED from unexpected sender {} for file ID: {}. Expected: {}",
                        senderOfAcceptance, fileId, transfer.getRecipientId());
            return;
        }

        if (transfer.getStatus() == FileTransferStatus.AWAITING_ACCEPTANCE) {
            logger.info("File transfer ID: {} accepted by recipient {}. Starting to send chunks.", fileId, senderOfAcceptance);
            // Status will be set to SENDING_CHUNKS within startSendingChunks
            startSendingChunks(fileId);
        } else {
            logger.warn("Received FILE_TRANSFER_ACCEPTED for file ID: {} which is not in AWAITING_ACCEPTANCE state. Current status: {}",
                        fileId, transfer.getStatus());
        }
    }


    /**
     * Starts sending the chunks for a previously initiated outgoing file transfer.
     *
     * @param fileId The ID of the file transfer to start sending.
     */
    private void startSendingChunks(String fileId) {
        OutgoingFileTransfer transfer = outgoingTransfers.get(fileId);
        if (transfer == null) {
            logger.error("Cannot start sending chunks: No outgoing transfer found for file ID: {}", fileId);
            return;
        }

        // Double check status before proceeding, could be called from handleFileTransferAccepted
        if (transfer.getStatus() != FileTransferStatus.AWAITING_ACCEPTANCE && transfer.getStatus() != FileTransferStatus.SENDING_CHUNKS) {
             if (transfer.getStatus() == FileTransferStatus.COMPLETED || transfer.getStatus() == FileTransferStatus.FAILED) {
                logger.warn("Chunks for file ID {} cannot be sent. Transfer is already completed/failed. Status: {}", fileId, transfer.getStatus());
                return;
            }
            // If it's in some other unexpected state, log and potentially fail.
            // For now, we proceed if it was AWAITING_ACCEPTANCE or if retrying (though retry isn't implemented yet)
        }


        transfer.setStatus(FileTransferStatus.SENDING_CHUNKS);
        logger.info("Starting to send chunks for file ID: {}, File: {}", fileId, transfer.getFilePath());
        final String localUserId = passkeyAuthService.getLocalUserId(); // Ensure localUserId is effectively final for lambda

        fileTransferExecutor.submit(() -> {
            try (InputStream inputStream = new FileInputStream(transfer.getFilePath())) {
                byte[] buffer = new byte[CHUNK_SIZE_BYTES];
                int bytesRead;
                int chunkIndex = 0;

                if (transfer.getFileInfo().getFileSize() == 0) { // Handle zero-byte file
                     FileChunk emptyChunk = new FileChunk(fileId, 0, new byte[0]);
                     Message chunkMessage = messageService.createFileChunkMessage(localUserId, transfer.getRecipientId(), emptyChunk);
                     p2pConnectionManager.sendMessage(transfer.getRecipientId(), chunkMessage);
                     transfer.setChunksSent(1);
                     logger.debug("Sent empty chunk for zero-byte file ID: {}", fileId);
                     chunkIndex = 1; // Mark as one chunk sent
                } else {
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        if (transfer.getStatus() != FileTransferStatus.SENDING_CHUNKS) {
                            logger.warn("File transfer {} was cancelled or failed while sending chunks. Aborting.", fileId);
                            // Do not send FILE_TRANSFER_ERROR here as the status change should have triggered it.
                            return; // Stop sending
                        }
                        byte[] actualChunkData = new byte[bytesRead];
                        System.arraycopy(buffer, 0, actualChunkData, 0, bytesRead);

                        FileChunk fileChunk = new FileChunk(fileId, chunkIndex, actualChunkData);
                        Message chunkMessage = messageService.createFileChunkMessage(localUserId, transfer.getRecipientId(), fileChunk);
                        p2pConnectionManager.sendMessage(transfer.getRecipientId(), chunkMessage);

                        transfer.setChunksSent(chunkIndex + 1);
                        logger.debug("Sent chunk {}/{} for file ID: {}", chunkIndex + 1, transfer.getFileInfo().getTotalChunks(), fileId);
                        chunkIndex++;
                    }
                }

                if (chunkIndex == transfer.getFileInfo().getTotalChunks()) {
                    transfer.setStatus(FileTransferStatus.COMPLETED);
                    logger.info("All chunks sent for file ID: {}. Transfer completed from sender side.", fileId);
                    Message completeMessage = messageService.createFileTransferCompleteMessage(localUserId, transfer.getRecipientId(), fileId);
                    p2pConnectionManager.sendMessage(transfer.getRecipientId(), completeMessage);
                } else if (transfer.getStatus() == FileTransferStatus.SENDING_CHUNKS) { // Only if not already failed/cancelled
                    // This case should ideally not happen if totalChunks is calculated correctly and file isn't modified
                    transfer.setStatus(FileTransferStatus.FAILED);
                    logger.error("Mismatch in sent chunks ({}) and total chunks ({}) for file ID: {}. Marking as failed.",
                                 chunkIndex, transfer.getFileInfo().getTotalChunks(), fileId);
                    Message errorMessage = messageService.createFileTransferErrorMessage(localUserId, transfer.getRecipientId(), fileId, "CHUNK_SENDING_MISMATCH", "Chunk sending mismatch");
                    p2pConnectionManager.sendMessage(transfer.getRecipientId(), errorMessage);
                }

            } catch (IOException e) {
                logger.error("IOException while sending chunks for file ID: {}. Error: {}", fileId, e.getMessage(), e);
                if (transfer.getStatus() != FileTransferStatus.FAILED) { // Avoid double error reporting
                    transfer.setStatus(FileTransferStatus.FAILED);
                    Message errorMessage = messageService.createFileTransferErrorMessage(localUserId, transfer.getRecipientId(), fileId, "IO_ERROR_SENDING", "IO error during sending: " + e.getMessage());
                    p2pConnectionManager.sendMessage(transfer.getRecipientId(), errorMessage);
                }
            } catch (Exception e) {
                logger.error("Unexpected error while sending chunks for file ID: {}. Error: {}", fileId, e.getMessage(), e);
                 if (transfer.getStatus() != FileTransferStatus.FAILED) {
                    transfer.setStatus(FileTransferStatus.FAILED);
                    Message errorMessage = messageService.createFileTransferErrorMessage(localUserId, transfer.getRecipientId(), fileId, "UNEXPECTED_ERROR_SENDING", "Unexpected error during sending: " + e.getMessage());
                    p2pConnectionManager.sendMessage(transfer.getRecipientId(), errorMessage);
                }
            }
        });
    }

    /**
     * Handles the reception of file information for an incoming file transfer.
     * Validates the fileInfo and senderId, logs the receipt, checks for duplicate transfers,
     * sanitizes the filename, resolves the target path in the couchat_incoming_files directory,
     * and creates a new IncomingFileTransfer object.
     *
     * @param fileInfo The file information received.
     * @param senderId The ID of the sender.
     */
    public void handleIncomingFileInfo(FileInfo fileInfo, String senderId) {
        if (fileInfo == null || senderId == null || senderId.isEmpty()) {
            logger.warn("Received invalid FileInfo or senderId. FileInfo: {}, SenderId: {}", fileInfo, senderId);
            return;
        }
        if (fileInfo.getFileId() == null || fileInfo.getFileId().isEmpty()) {
            logger.warn("Received FileInfo with null or empty fileId from sender {}. Ignoring. FileInfo: {}", senderId, fileInfo);
            return;
        }

        logger.info("Received FILE_INFO from sender {}: File ID: {}, Name: {}, Size: {}, Total Chunks: {}",
                    senderId, fileInfo.getFileId(), fileInfo.getFileName(), fileInfo.getFileSize(), fileInfo.getTotalChunks());

        if (incomingTransfers.containsKey(fileInfo.getFileId())) {
            logger.warn("Already processing an incoming file transfer with ID: {}. Ignoring duplicate FILE_INFO from {}.",
                        fileInfo.getFileId(), senderId);
            return;
        }

        String sanitizedFileName = sanitizeFileName(fileInfo.getFileName());
        Path targetFilePath = this.incomingFilesPath.resolve(sanitizedFileName);

        int collisionCount = 0;
        String baseName = sanitizedFileName;
        String extension = "";
        int dotIndex = sanitizedFileName.lastIndexOf('.');
        if (dotIndex > 0 && dotIndex < sanitizedFileName.length() - 1) {
            baseName = sanitizedFileName.substring(0, dotIndex);
            extension = sanitizedFileName.substring(dotIndex);
        }

        while (Files.exists(targetFilePath)) {
            collisionCount++;
            targetFilePath = this.incomingFilesPath.resolve(baseName + "(" + collisionCount + ")" + extension);
            if (collisionCount > 100) {
                logger.error("Too many file name collisions for base name '{}' in directory {}. Aborting transfer for fileId {}.",
                             baseName, this.incomingFilesPath, fileInfo.getFileId());
                // Send FILE_TRANSFER_REJECTED or FILE_TRANSFER_ERROR back to sender
                String localUserId = passkeyAuthService.getLocalUserId(); // Corrected
                if (localUserId != null) {
                    Message errorMessage = messageService.createFileTransferErrorMessage(localUserId, senderId, fileInfo.getFileId(), "FILENAME_COLLISION", "File name collision or storage issue on recipient side.");
                    p2pConnectionManager.sendMessage(senderId, errorMessage);
                }
                return;
            }
        }

        IncomingFileTransfer transfer = new IncomingFileTransfer(fileInfo.getFileId(), senderId, fileInfo, targetFilePath);
        transfer.setStatus(FileTransferStatus.AWAITING_ACCEPTANCE); // Initial status
        incomingTransfers.put(fileInfo.getFileId(), transfer);

        logger.info("Incoming file transfer offer received. File ID: {} from sender: {}. Target path: {}. Awaiting user acceptance.",
                    fileInfo.getFileId(), senderId, targetFilePath);

        // Removed auto-accept for prototype. Acceptance should be triggered by user via API.
        // String localUserId = passkeyAuthService.getLocalUserId();
        // if (localUserId != null) {
        //     Message acceptedMessage = messageService.createFileTransferAcceptedMessage(localUserId, senderId, fileInfo.getFileId());
        //     p2pConnectionManager.sendMessage(senderId, acceptedMessage);
        //     transfer.setStatus(FileTransferStatus.RECEIVING_CHUNKS);
        //     logger.info("Auto-accepted file transfer ID: {} from {}. Sent FILE_TRANSFER_ACCEPTED. Status set to RECEIVING_CHUNKS.", fileInfo.getFileId(), senderId);
        // } else {
        //     logger.error("Cannot auto-accept file transfer ID: {} from {}: Local Peer ID is null. Cannot send acceptance.", fileInfo.getFileId(), senderId);
        //     incomingTransfers.remove(fileInfo.getFileId());
        // }
    }

    private String sanitizeFileName(String fileName) {
        // Sanitize file name to prevent directory traversal or invalid characters
        // For simplicity, let's just replace some common problematic characters
        // TODO: Enhance sanitization as per requirements (e.g., removing or encoding special characters)
        return fileName.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    /**
     * Handles the reception of a file chunk for an ongoing file transfer.
     * Validates the fileChunk and senderId, retrieves the IncomingFileTransfer,
     * validates transfer status and chunk index, and appends chunk data to the target file.
     * If all chunks are received, finalizes the file.
     *
     * @param fileChunk The file chunk received.
     * @param senderId  The ID of the sender.
     */
    public void handleIncomingFileChunk(FileChunk fileChunk, String senderId) {
        if (fileChunk == null || fileChunk.getFileId() == null || senderId == null || senderId.isEmpty()) {
            logger.warn("Received invalid FileChunk or senderId. FileChunk: {}, SenderId: {}", fileChunk, senderId);
            return;
        }

        String fileId = fileChunk.getFileId();
        IncomingFileTransfer transfer = incomingTransfers.get(fileId);

        if (transfer == null) {
            logger.warn("Received chunk for unknown or non-active file transfer ID: {} from sender: {}. Ignoring.", fileId, senderId);
            // TODO: Optionally send a FILE_TRANSFER_ERROR if this is unexpected.
            return;
        }

        if (!transfer.getSenderId().equals(senderId)) {
            logger.warn("Received chunk for file ID: {} from unexpected sender: {}. Expected: {}. Ignoring.",
                        fileId, senderId, transfer.getSenderId());
            return;
        }

        if (transfer.getStatus() != FileTransferStatus.RECEIVING_CHUNKS) {
            logger.warn("Received chunk for file ID: {} which is not in RECEIVING_CHUNKS state. Current status: {}. Ignoring chunk.",
                        fileId, transfer.getStatus());
            return;
        }

        // TODO: Validate chunk index for sequence, duplicates, or missing chunks.
        // For now, appending sequentially as received.
        // More robust handling would involve managing a bitfield or list of received chunks.

        try {
            boolean isComplete = transfer.addChunk(fileChunk.getChunkIndex(), fileChunk.getData()); // This method should handle writing to file
            logger.debug("Received and processed chunk {} for file ID: {}. Total received: {}/{}",
                         fileChunk.getChunkIndex() + 1, fileId, transfer.getChunksReceivedCount(), transfer.getFileInfo().getTotalChunks());

            if (isComplete) {
                transfer.setStatus(FileTransferStatus.COMPLETED);
                logger.info("All chunks received for file ID: {}. File saved to: {}. Transfer completed on receiver side.",
                            fileId, transfer.getTargetPath().toString());
                // Optionally, send a final ACK to the sender, though sender's FILE_TRANSFER_COMPLETE serves a similar role.
            }

        } catch (IOException e) {
            logger.error("IOException while writing chunk for file ID: {}. Chunk index: {}. Error: {}",
                         fileId, fileChunk.getChunkIndex(), e.getMessage(), e);
            transfer.setStatus(FileTransferStatus.FAILED);
            transfer.closeAndCleanupFile(); // Ensure partial file is deleted
            // Send error message back to sender
            String localUserId = passkeyAuthService.getLocalUserId(); // Corrected
            if (localUserId != null) {
                Message errorMessage = messageService.createFileTransferErrorMessage(localUserId, senderId, fileId, "IO_ERROR_RECEIVING_CHUNK", "IO error on recipient while writing chunk: " + e.getMessage());
                p2pConnectionManager.sendMessage(senderId, errorMessage);
            }
        } catch (Exception e) {
            logger.error("Unexpected error while processing chunk for file ID: {}. Error: {}", fileId, e.getMessage(), e);
            transfer.setStatus(FileTransferStatus.FAILED);
            transfer.closeAndCleanupFile();
            String localUserId = passkeyAuthService.getLocalUserId(); // Corrected
            if (localUserId != null) {
                Message errorMessage = messageService.createFileTransferErrorMessage(localUserId, senderId, fileId, "UNEXPECTED_ERROR_PROCESSING_CHUNK", "Unexpected error on recipient processing chunk: " + e.getMessage());
                p2pConnectionManager.sendMessage(senderId, errorMessage);
            }
        }
    }

    /**
     * Handles the FILE_TRANSFER_COMPLETE message from the sender.
     *
     * @param fileId The ID of the completed file transfer.
     * @param senderId The peer ID of the sender who completed the transfer.
     */
    public void handleFileTransferCompleteMessage(String fileId, String senderId) {
        IncomingFileTransfer transfer = incomingTransfers.get(fileId);
        if (transfer == null) {
            logger.warn("Received FILE_TRANSFER_COMPLETE for unknown file ID: {} from {}", fileId, senderId);
            return;
        }

        if (!transfer.getSenderId().equals(senderId)) {
            logger.warn("Received FILE_TRANSFER_COMPLETE from unexpected sender {} for file ID: {}. Expected: {}",
                        senderId, fileId, transfer.getSenderId());
            return;
        }

        // If receiver already marked as complete, this is just a confirmation.
        if (transfer.getStatus() == FileTransferStatus.COMPLETED) {
            logger.info("Confirmed completion for file transfer ID: {} from sender {}. Receiver already marked as complete.", fileId, senderId);
        } else if (transfer.getStatus() == FileTransferStatus.RECEIVING_CHUNKS) {
            // This might happen if the complete message arrives before the last chunk is fully processed by the receiver,
            // or if there's a slight desync. Receiver relies on its own chunk counting.
            logger.info("Received FILE_TRANSFER_COMPLETE for file ID: {} from {}. Receiver status: {}. Awaiting all chunks.",
                        fileId, senderId, transfer.getStatus());
            // We could potentially verify if all chunks are indeed received here.
            // If transfer.getChunksReceived() == transfer.getFileInfo().getTotalChunks(), then finalize.
            // However, handleIncomingFileChunk should be the primary place to set COMPLETED status.
        } else {
            logger.warn("Received FILE_TRANSFER_COMPLETE for file ID: {} from {} but current status is {}.",
                        fileId, senderId, transfer.getStatus());
        }
        // No specific action needed if already completed or still receiving,
        // as completion is primarily determined by receiving all chunks.
    }

    /**
     * Handles the FILE_TRANSFER_ERROR message from the other peer.
     *
     * @param fileId The ID of the failed file transfer.
     * @param senderOfError The peer ID of the sender of the error message.
     * @param errorCode An optional error code.
     * @param errorMessageText The error message.
     */
    public void handleFileTransferErrorMessage(String fileId, String senderOfError, String errorCode, String errorMessageText) {
        logger.error("Received FILE_TRANSFER_ERROR from peer {}: File ID: {}, Code: {}, Message: {}",
                     senderOfError, fileId, errorCode, errorMessageText);

        // Check if it's for an outgoing transfer we initiated
        OutgoingFileTransfer outgoingTransfer = outgoingTransfers.get(fileId);
        if (outgoingTransfer != null && outgoingTransfer.getRecipientId().equals(senderOfError)) {
            logger.error("Outgoing file transfer {} to {} failed. Reason from peer: {} - {}",
                         fileId, senderOfError, errorCode, errorMessageText);
            outgoingTransfer.setStatus(FileTransferStatus.FAILED);
            // TODO: Notify UI about the failure of the outgoing transfer
            // outgoingTransfers.remove(fileId); // Or keep for history/retry
            return;
        }

        // Check if it's for an incoming transfer we are receiving
        IncomingFileTransfer incomingTransfer = incomingTransfers.get(fileId);
        if (incomingTransfer != null && incomingTransfer.getSenderId().equals(senderOfError)) {
            logger.error("Incoming file transfer {} from {} failed. Reason from peer: {} - {}",
                         fileId, senderOfError, errorCode, errorMessageText);
            incomingTransfer.setStatus(FileTransferStatus.FAILED);
            // TODO: Notify UI about the failure of the incoming transfer
            // incomingTransfers.remove(fileId); // Or keep for history/retry
            return;
        }

        logger.warn("Received a FILE_TRANSFER_ERROR for an unknown or mismatched transfer. File ID: {}, Sender of Error: {}",
                    fileId, senderOfError);
    }

    public void handleFileTransferCompletedBySender(String fileId, String senderId) {
        IncomingFileTransfer transfer = incomingTransfers.get(fileId);
        if (transfer == null) {
            logger.warn("Received FILE_TRANSFER_COMPLETE for unknown or non-active incoming file ID: {} from sender: {}", fileId, senderId);
            return;
        }

        if (!transfer.getSenderId().equals(senderId)) {
            logger.warn("Received FILE_TRANSFER_COMPLETE from unexpected sender {} for file ID: {}. Expected: {}",
                        senderId, fileId, transfer.getSenderId());
            return;
        }

        // This message means the sender has sent all chunks.
        // The receiver (this instance) should verify if all chunks were indeed received.
        logger.info("Sender {} reported FILE_TRANSFER_COMPLETE for file ID: {}. Verifying received chunks.", senderId, fileId);

        if (transfer.getStatus() == FileTransferStatus.RECEIVING_CHUNKS || transfer.getStatus() == FileTransferStatus.AWAITING_ACCEPTANCE ) { // Corrected: AWAITING_ACCEPTANCE to AWAITING_CHUNKS if that's a valid state before receiving
            // It's more likely that if FILE_TRANSFER_COMPLETE is received, status should be RECEIVING_CHUNKS
            // If AWAITING_CHUNKS is a valid status, it should be included.
            // For now, assuming AWAITING_CHUNKS is not a typical state when sender sends COMPLETE.
            // Let's stick to RECEIVING_CHUNKS for now or consider if AWAITING_CHUNKS is a valid intermediate state.
            // The error log mentioned AWAITING_CHUNKS was missing, so let's assume this was a typo and it should be RECEIVING_CHUNKS
            // or that AWAITING_CHUNKS needs to be added to FileTransferStatus enum.
            // For now, I will assume the original intent was to check if it's actively receiving.

            if (transfer.getStatus() == FileTransferStatus.RECEIVING_CHUNKS) { // More specific check
                if (transfer.areAllChunksReceived()) {
                    try {
                        transfer.assembleFile(); // This method now also sets status to COMPLETED
                        logger.info("Successfully assembled file ID: {} from sender: {}. Path: {}",
                                    fileId, senderId, transfer.getFinalFilePath());
                    } catch (IOException e) {
                        logger.error("Failed to assemble file ID: {} from sender: {}. Error: {}", fileId, senderId, e.getMessage(), e);
                        transfer.setStatus(FileTransferStatus.FAILED);
                        Message errorMessage = messageService.createFileTransferErrorMessage(
                            passkeyAuthService.getLocalUserId(),
                            senderId,
                            fileId,
                            "ASSEMBLY_FAILED",
                            "Receiver failed to assemble file: " + e.getMessage()
                        );
                        p2pConnectionManager.sendMessage(senderId, errorMessage);
                    }
                } else {
                    logger.warn("Sender {} reported FILE_TRANSFER_COMPLETE for file ID: {}, but not all chunks have been received locally. Expected: {}, Got: {}. Waiting for more chunks or timeout.",
                                senderId, fileId, transfer.getFileInfo().getTotalChunks(), transfer.getChunksReceivedCount());
                    // Do not change status yet, wait for more chunks or a timeout mechanism to declare it failed.
                    // The sender might have sent COMPLETE, but chunks might still be in transit or lost.
                }
            } else {
                 logger.warn("Received FILE_TRANSFER_COMPLETE for file ID: {} from sender: {} but status is {}. Verification might be premature.",
                            fileId, senderId, transfer.getStatus());
            }
        } else {
            logger.warn("Received FILE_TRANSFER_COMPLETE for file ID: {} from sender: {} but current status is {}. No action taken.",
                        fileId, senderId, transfer.getStatus());
        }
    }

    // TODO: Add methods to query transfer status, cancel transfers, etc.

    // Example of how to get an OutgoingFileTransfer (e.g., for UI updates)
    public OutgoingFileTransfer getOutgoingTransfer(String fileId) {
        return outgoingTransfers.get(fileId);
    }

    // Example of how to get an IncomingFileTransfer (e.g., for UI updates)
    public IncomingFileTransfer getIncomingTransfer(String fileId) {
        return incomingTransfers.get(fileId);
    }

    // Helper method to map P2P transfer status to Model transfer status
    private com.couchat.transfer.model.FileTransfer.FileTransferStatus mapP2PStatusToModelStatus(FileTransferStatus p2pStatus) {
        if (p2pStatus == null) {
            return com.couchat.transfer.model.FileTransfer.FileTransferStatus.FAILED; // Or some default
        }
        switch (p2pStatus) {
            case AWAITING_ACCEPTANCE:
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.PENDING;
            case ACCEPTED: // Added mapping for P2P ACCEPTED state
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.ACCEPTED;
            case SENDING_CHUNKS:
            case RECEIVING_CHUNKS:
            case AWAITING_CHUNKS: // Added mapping for P2P AWAITING_CHUNKS state
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.IN_PROGRESS;
            case COMPLETED:
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.COMPLETED;
            case FAILED:
                // TIMED_OUT is not in FileTransferStatus enum, so removed
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.FAILED;
            case REJECTED: // Added mapping for P2P REJECTED state
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.REJECTED;
            case CANCELLED:
                // CANCELLED_BY_SENDER and CANCELLED_BY_RECEIVER are not in FileTransferStatus enum
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.CANCELLED;
            default:
                logger.warn("Unhandled P2P FileTransferStatus: {}. Defaulting to FAILED for model.", p2pStatus);
                return com.couchat.transfer.model.FileTransfer.FileTransferStatus.FAILED;
        }
    }

    public Optional<com.couchat.transfer.model.FileTransfer> getFileTransferById(String fileId) {
        OutgoingFileTransfer oft = outgoingTransfers.get(fileId);
        if (oft != null) {
            FileInfo info = oft.getFileInfo();
            long modelFileSize = info.getFileSize();
            if (modelFileSize == 0) {
                logger.warn("Mapping 0-byte file size to 1 for FileTransfer model due to constructor constraint for fileId: {}", fileId);
                modelFileSize = 1; // Workaround for model constraint
            }
            try {
                com.couchat.transfer.model.FileTransfer modelFt = new com.couchat.transfer.model.FileTransfer(
                        fileId,
                        "P2P-O-" + fileId, // Placeholder messageId
                        info.getFileName(),
                        modelFileSize,
                        info.getFileType(),
                        oft.getFilePath(),
                        mapP2PStatusToModelStatus(oft.getStatus()),
                        null, // hashValue
                        Instant.now(), // createdAt - P2P object doesn't store this
                        Instant.now()  // updatedAt
                );
                return Optional.of(modelFt);
            } catch (IllegalArgumentException e) {
                logger.error("Error constructing FileTransfer model for outgoing transfer {}: {}", fileId, e.getMessage());
                return Optional.empty();
            }
        }

        IncomingFileTransfer ift = incomingTransfers.get(fileId);
        if (ift != null) {
            FileInfo info = ift.getFileInfo();
            long modelFileSize = info.getFileSize();
            if (modelFileSize == 0) {
                logger.warn("Mapping 0-byte file size to 1 for FileTransfer model due to constructor constraint for fileId: {}", fileId);
                modelFileSize = 1; // Workaround for model constraint
            }
            try {
                com.couchat.transfer.model.FileTransfer modelFt = new com.couchat.transfer.model.FileTransfer(
                        fileId,
                        "P2P-I-" + fileId, // Placeholder messageId
                        info.getFileName(),
                        modelFileSize,
                        info.getFileType(),
                        ift.getTargetPath() != null ? ift.getTargetPath().toString() : null,
                        mapP2PStatusToModelStatus(ift.getStatus()),
                        null, // hashValue
                        Instant.now(), // createdAt
                        Instant.now()  // updatedAt
                );
                return Optional.of(modelFt);
            } catch (IllegalArgumentException e) {
                logger.error("Error constructing FileTransfer model for incoming transfer {}: {}", fileId, e.getMessage());
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public boolean acceptIncomingTransfer(String fileId) {
        IncomingFileTransfer transfer = incomingTransfers.get(fileId);
        if (transfer == null) {
            logger.warn("Cannot accept transfer {}: not found.", fileId);
            return false;
        }
        if (transfer.getStatus() != FileTransferStatus.AWAITING_ACCEPTANCE) {
            logger.warn("Cannot accept transfer {}: not in AWAITING_ACCEPTANCE state. Current status: {}", fileId, transfer.getStatus());
            return false;
        }

        String localUserId = passkeyAuthService.getLocalUserId();
        if (localUserId == null) {
            logger.error("Cannot accept file transfer ID: {}: Local User ID is null. Cannot send acceptance.", fileId);
            // Optionally set transfer status to FAILED here if that's desired behavior
            // transfer.setStatus(FileTransferStatus.FAILED);
            return false;
        }

        transfer.setStatus(FileTransferStatus.RECEIVING_CHUNKS); // Or an intermediate ACCEPTED status first
        Message acceptedMessage = messageService.createFileTransferAcceptedMessage(localUserId, transfer.getSenderId(), fileId);
        // boolean messageSent = p2pConnectionManager.sendMessage(transfer.getSenderId(), acceptedMessage);
        // Assuming sendMessage is void and logs errors internally or throws them.
        // For now, we proceed optimistically after calling sendMessage.
        p2pConnectionManager.sendMessage(transfer.getSenderId(), acceptedMessage);
        logger.info("User accepted file transfer ID: {} from {}. Sent FILE_TRANSFER_ACCEPTED. Status set to RECEIVING_CHUNKS.", fileId, transfer.getSenderId());
        return true; // Assume success if no exception from sendMessage

        // if (messageSent) {
        //     logger.info("User accepted file transfer ID: {} from {}. Sent FILE_TRANSFER_ACCEPTED. Status set to RECEIVING_CHUNKS.", fileId, transfer.getSenderId());
        //     return true;
        // } else {
        //     logger.error("Failed to send FILE_TRANSFER_ACCEPTED message for file ID: {}. Rolling back status.", fileId);
        //     transfer.setStatus(FileTransferStatus.AWAITING_ACCEPTANCE); // Rollback status
        //     // Consider further error handling or retry mechanisms
        //     return false;
        // }
    }

    public boolean rejectIncomingTransfer(String fileId) {
        IncomingFileTransfer transfer = incomingTransfers.get(fileId);
        if (transfer == null) {
            logger.warn("Cannot reject transfer {}: not found.", fileId);
            return false;
        }
         if (transfer.getStatus() != FileTransferStatus.AWAITING_ACCEPTANCE) {
            logger.warn("Cannot reject transfer {}: not in AWAITING_ACCEPTANCE state. Current status: {}", fileId, transfer.getStatus());
            // If already rejected or failed, could return true or false based on desired idempotency
            return false;
        }

        String localUserId = passkeyAuthService.getLocalUserId();
        if (localUserId == null) {
            logger.warn("Local user ID is null, cannot send rejection message for file transfer ID: {}. Marking as rejected locally.", fileId);
            transfer.setStatus(FileTransferStatus.REJECTED);
            incomingTransfers.remove(fileId); // Clean up
            return true; // Local rejection successful
        }

        transfer.setStatus(FileTransferStatus.REJECTED);
        // Assuming createFileTransferErrorMessage can be used for rejection, or a specific rejection message exists
        Message rejectedMessage = messageService.createFileTransferErrorMessage(localUserId, transfer.getSenderId(), fileId, "USER_REJECTED", "User rejected the file transfer.");
        p2pConnectionManager.sendMessage(transfer.getSenderId(), rejectedMessage); // Send regardless of success for now, log if fails

        logger.info("User rejected file transfer ID: {} from {}. Sent rejection notification.", fileId, transfer.getSenderId());
        incomingTransfers.remove(fileId); // Clean up rejected transfer from active map
        return true;
    }
}
