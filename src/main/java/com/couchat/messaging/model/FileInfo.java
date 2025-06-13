package com.couchat.messaging.model;

import java.io.Serializable;

/**
 * Represents metadata for a file to be transferred.
 * This object is typically used as the payload for a {@link Message} of type {@link Message.MessageType#FILE_INFO}.
 */
public class FileInfo implements Serializable {
    private static final long serialVersionUID = 1L; // For Serializable interface

    private String fileId;      // Unique ID for this file transfer operation
    private String fileName;
    private long fileSize;      // Total size of the file in bytes
    private String fileType;    // MIME type of the file, if available
    private int totalChunks;    // Total number of chunks the file will be split into
    // Optionally, add a checksum for the entire file (e.g., SHA-256)
    // private String fileChecksum;

    /**
     * Default constructor for deserialization.
     */
    public FileInfo() {
    }

    /**
     * Constructs a new FileInfo object.
     *
     * @param fileId     A unique identifier for this file transfer.
     * @param fileName   The original name of the file.
     * @param fileSize   The total size of the file in bytes.
     * @param fileType   The MIME type of the file (can be null).
     * @param totalChunks The total number of chunks the file will be divided into.
     */
    public FileInfo(String fileId, String fileName, long fileSize, String fileType, int totalChunks) {
        this.fileId = fileId;
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.fileType = fileType;
        this.totalChunks = totalChunks;
    }

    // Getters and Setters
    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    public int getTotalChunks() {
        return totalChunks;
    }

    public void setTotalChunks(int totalChunks) {
        this.totalChunks = totalChunks;
    }

    @Override
    public String toString() {
        return "FileInfo{" +
               "fileId='" + fileId + '\'' +
               ", fileName='" + fileName + '\'' +
               ", fileSize=" + fileSize +
               ", fileType='" + fileType + '\'' +
               ", totalChunks=" + totalChunks +
               '}';
    }
}

