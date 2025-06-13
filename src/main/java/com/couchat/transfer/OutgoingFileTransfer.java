package com.couchat.transfer;

import com.couchat.messaging.model.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an active outgoing file transfer.
 * Manages the state of a file being sent to a peer.
 */
public class OutgoingFileTransfer {
    private static final Logger logger = LoggerFactory.getLogger(OutgoingFileTransfer.class);

    private final String fileId;
    private final String filePath;
    private final String recipientId;
    private final FileInfo fileInfo;
    private FileTransferStatus status;
    private int chunksSent;
    private long bytesSent; // Optional: for more detailed progress tracking

    public OutgoingFileTransfer(String fileId, String filePath, String recipientId, FileInfo fileInfo) {
        this.fileId = fileId;
        this.filePath = filePath;
        this.recipientId = recipientId;
        this.fileInfo = fileInfo;
        this.status = FileTransferStatus.AWAITING_ACCEPTANCE; // Initial status after sending FILE_INFO
        this.chunksSent = 0;
        this.bytesSent = 0;
    }

    public String getFileId() {
        return fileId;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getRecipientId() {
        return recipientId;
    }

    public FileInfo getFileInfo() {
        return fileInfo;
    }

    public FileTransferStatus getStatus() {
        return status;
    }

    public void setStatus(FileTransferStatus status) {
        logger.debug("Outgoing transfer {} status changed from {} to {}", fileId, this.status, status);
        this.status = status;
    }

    public int getChunksSent() {
        return chunksSent;
    }

    public void setChunksSent(int chunksSent) {
        this.chunksSent = chunksSent;
    }

    public long getBytesSent() {
        return bytesSent;
    }

    public void incrementBytesSent(long amount) {
        this.bytesSent += amount;
    }

    // Add any other relevant methods, e.g., for pausing, cancelling, or retrying.
}

