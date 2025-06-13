package com.couchat.transfer.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a file transfer in the CouChat system.
 * This class maps to the 'file_transfers' table in the database.
 */
public class FileTransfer {

    private final String fileId;          // Primary Key, UUID
    private final String messageId;       // FK to messages table (the FILE_INFO message)
    private String fileName;
    private long fileSize;
    private String mimeType;
    private String localPath;           // Local path where the file is stored/downloaded
    private FileTransferStatus status;
    private String hashValue;           // Hash of the file for integrity checks
    private final Instant createdAt;
    private Instant updatedAt;

    public enum FileTransferStatus {
        PENDING,    // Initial state, info sent, awaiting acceptance
        ACCEPTED,   // Recipient accepted the transfer
        IN_PROGRESS,
        COMPLETED,
        FAILED,
        REJECTED,   // Recipient rejected the transfer
        CANCELLED   // Transfer cancelled by sender or recipient
    }

    /**
     * Constructor for creating a new file transfer record.
     *
     * @param messageId The ID of the FILE_INFO message initiating this transfer.
     * @param fileName The name of the file.
     * @param fileSize The size of the file in bytes.
     * @param mimeType The MIME type of the file.
     */
    public FileTransfer(String messageId, String fileName, long fileSize, String mimeType) {
        this.fileId = UUID.randomUUID().toString();
        this.messageId = Objects.requireNonNull(messageId, "Message ID cannot be null.");
        this.fileName = Objects.requireNonNull(fileName, "File name cannot be null.");
        if (fileSize <= 0) {
            throw new IllegalArgumentException("File size must be positive.");
        }
        this.fileSize = fileSize;
        this.mimeType = mimeType;
        this.status = FileTransferStatus.PENDING;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    /**
     * Constructor for loading an existing file transfer record from the database.
     */
    public FileTransfer(String fileId, String messageId, String fileName, long fileSize, String mimeType,
                        String localPath, FileTransferStatus status, String hashValue,
                        Instant createdAt, Instant updatedAt) {
        this.fileId = Objects.requireNonNull(fileId, "File ID cannot be null.");
        this.messageId = Objects.requireNonNull(messageId, "Message ID cannot be null.");
        this.fileName = Objects.requireNonNull(fileName, "File name cannot be null.");
        this.fileSize = fileSize;
        this.mimeType = mimeType;
        this.localPath = localPath;
        this.status = Objects.requireNonNull(status, "Status cannot be null.");
        this.hashValue = hashValue;
        this.createdAt = Objects.requireNonNull(createdAt, "Creation timestamp cannot be null.");
        this.updatedAt = Objects.requireNonNull(updatedAt, "Update timestamp cannot be null.");
    }

    // Getters
    public String getFileId() { return fileId; }
    public String getMessageId() { return messageId; }
    public String getFileName() { return fileName; }
    public long getFileSize() { return fileSize; }
    public String getMimeType() { return mimeType; }
    public String getLocalPath() { return localPath; }
    public FileTransferStatus getStatus() { return status; }
    public String getHashValue() { return hashValue; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    // Setters for mutable fields
    public void setFileName(String fileName) {
        this.fileName = Objects.requireNonNull(fileName, "File name cannot be null.");
    }

    public void setFileSize(long fileSize) {
        if (fileSize <= 0) {
            throw new IllegalArgumentException("File size must be positive.");
        }
        this.fileSize = fileSize;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }

    public void setLocalPath(String localPath) {
        this.localPath = localPath;
    }

    public void setStatus(FileTransferStatus status) {
        this.status = Objects.requireNonNull(status, "Status cannot be null.");
    }

    public void setHashValue(String hashValue) {
        this.hashValue = hashValue;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = Objects.requireNonNull(updatedAt, "Update timestamp cannot be null.");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FileTransfer that = (FileTransfer) o;
        return Objects.equals(fileId, that.fileId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fileId);
    }

    @Override
    public String toString() {
        return "FileTransfer{" +
                "fileId='" + fileId + '\'' +
                ", messageId='" + messageId + '\'' +
                ", fileName='" + fileName + '\'' +
                ", fileSize=" + fileSize +
                ", status=" + status +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}

