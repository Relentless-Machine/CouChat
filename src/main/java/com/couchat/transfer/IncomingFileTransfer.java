package com.couchat.transfer;

import com.couchat.messaging.model.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Represents an active incoming file transfer.
 * Manages the reception of file chunks and writing them to a target file.
 */
public class IncomingFileTransfer {
    private static final Logger logger = LoggerFactory.getLogger(IncomingFileTransfer.class);

    private final String fileId;
    private final String senderId;
    private final FileInfo fileInfo;
    private final Path targetPath;
    private FileTransferStatus status;
    private long bytesReceived;
    private int chunksReceived;
    private OutputStream fileOutputStream;

    public IncomingFileTransfer(String fileId, String senderId, FileInfo fileInfo, Path targetPath) {
        this.fileId = fileId;
        this.senderId = senderId;
        this.fileInfo = fileInfo;
        this.targetPath = targetPath;
        this.status = FileTransferStatus.AWAITING_ACCEPTANCE; // Initial status
        this.bytesReceived = 0;
        this.chunksReceived = 0;
        // Output stream will be opened when transfer is accepted and first chunk arrives or is about to arrive.
    }

    public String getFileId() {
        return fileId;
    }

    public String getSenderId() {
        return senderId;
    }

    public FileInfo getFileInfo() {
        return fileInfo;
    }

    public Path getTargetPath() {
        return targetPath;
    }

    public FileTransferStatus getStatus() {
        return status;
    }

    public void setStatus(FileTransferStatus status) {
        logger.debug("Incoming transfer {} status changed from {} to {}", fileId, this.status, status);
        this.status = status;
    }

    public long getBytesReceived() {
        return bytesReceived;
    }

    public int getChunksReceived() {
        return chunksReceived;
    }

    /**
     * Adds a received chunk's data to the file. Opens the file output stream if not already open.
     *
     * @param chunkData The byte array of the chunk data.
     * @return true if all chunks have been received, false otherwise.
     * @throws IOException If an I/O error occurs while opening or writing to the file.
     */
    public synchronized boolean addChunk(byte[] chunkData) throws IOException {
        if (status != FileTransferStatus.RECEIVING_CHUNKS) {
            logger.warn("Attempted to add chunk to transfer {} which is not in RECEIVING_CHUNKS state. Status: {}", fileId, status);
            // Optionally throw an exception or handle as an error
            return false;
        }

        if (fileOutputStream == null) {
            // Ensure parent directory exists (though FileTransferService should have handled this for the base incoming dir)
            Path parentDir = targetPath.getParent();
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
            }
            // Open with CREATE_NEW to prevent overwriting an existing file unexpectedly at this stage.
            // If a file with the same name (after sanitization and collision resolution) exists,
            // FileTransferService should have handled it. This is an additional safeguard.
            try {
                fileOutputStream = Files.newOutputStream(targetPath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                logger.info("Opened file output stream for incoming transfer {}: {}", fileId, targetPath);
            } catch (IOException e) {
                logger.error("Failed to create/open file for incoming transfer {}: {}. Error: {}", fileId, targetPath, e.getMessage(), e);
                setStatus(FileTransferStatus.FAILED);
                throw e; // Propagate error
            }
        }

        if (chunkData != null && chunkData.length > 0) {
            fileOutputStream.write(chunkData);
            bytesReceived += chunkData.length;
        }
        chunksReceived++;

        if (chunksReceived >= fileInfo.getTotalChunks()) {
            // All expected chunks received
            closeStream(); // Close the stream as we are done
            if (bytesReceived != fileInfo.getFileSize()) {
                logger.warn("File transfer {} completed, but received bytes ({}) do not match expected file size ({}).",
                            fileId, bytesReceived, fileInfo.getFileSize());
                // This could indicate an issue, potentially mark as error or handle based on policy
                // For now, we will still mark as complete if all chunks are in.
            }
            setStatus(FileTransferStatus.COMPLETED);
            return true;
        }
        return false;
    }

    /**
     * Closes the file output stream if it's open.
     * Should be called when the transfer is completed, failed, or cancelled.
     */
    private void closeStream() {
        if (fileOutputStream != null) {
            try {
                fileOutputStream.flush();
                fileOutputStream.close();
                logger.info("Closed file output stream for transfer {}: {}", fileId, targetPath);
            } catch (IOException e) {
                logger.error("Error closing file output stream for transfer {}: {}. Error: {}", fileId, targetPath, e.getMessage(), e);
            }
            fileOutputStream = null;
        }
    }

    /**
     * Closes the file output stream and deletes the partially downloaded file.
     * Used when the transfer fails or is cancelled.
     */
    public void closeAndCleanupFile() {
        closeStream();
        if (status == FileTransferStatus.FAILED || status == FileTransferStatus.CANCELLED || status == FileTransferStatus.REJECTED) {
            try {
                if (Files.exists(targetPath)) {
                    Files.delete(targetPath);
                    logger.info("Deleted partially downloaded file for transfer {}: {}", fileId, targetPath);
                }
            } catch (IOException e) {
                logger.error("Error deleting partially downloaded file for transfer {}: {}. Error: {}", fileId, targetPath, e.getMessage(), e);
            }
        }
    }
}

