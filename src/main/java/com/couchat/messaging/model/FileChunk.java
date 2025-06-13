package com.couchat.messaging.model;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Represents a chunk of a file being transferred.
 * This object is typically used as the payload for a {@link Message} of type {@link Message.MessageType#FILE_CHUNK}.
 */
public class FileChunk implements Serializable {
    private static final long serialVersionUID = 1L; // For Serializable interface

    private String fileId;      // Unique ID for the file transfer operation this chunk belongs to
    private int chunkIndex;     // 0-based index of this chunk
    private byte[] data;        // The actual byte data of the chunk
    // Optionally, add a checksum for this chunk (e.g., CRC32 or part of SHA-256)
    // private String chunkChecksum;

    /**
     * Default constructor for deserialization.
     */
    public FileChunk() {
    }

    /**
     * Constructs a new FileChunk object.
     *
     * @param fileId     The unique identifier for the file transfer operation.
     * @param chunkIndex The 0-based index of this chunk.
     * @param data       The byte array containing the chunk's data.
     */
    public FileChunk(String fileId, int chunkIndex, byte[] data) {
        this.fileId = fileId;
        this.chunkIndex = chunkIndex;
        this.data = data;
    }

    // Getters and Setters
    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public int getChunkIndex() {
        return chunkIndex;
    }

    public void setChunkIndex(int chunkIndex) {
        this.chunkIndex = chunkIndex;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "FileChunk{" +
               "fileId='" + fileId + '\'' +
               ", chunkIndex=" + chunkIndex +
               ", dataSize=" + (data != null ? data.length : 0) + " bytes" +
               '}';
    }
}

