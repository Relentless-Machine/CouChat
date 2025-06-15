// filepath: F:/Git/CouChat/src/main/java/com/couchat/transfer/IncomingFileTransfer.java
package com.couchat.transfer;

import com.couchat.messaging.model.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.BitSet;

/**
 * Represents an active incoming file transfer.
 * Manages the reception of file chunks and writing them to a target file.
 */
public class IncomingFileTransfer {
    private static final Logger logger = LoggerFactory.getLogger(IncomingFileTransfer.class);

    private final String fileId;
    private final String senderId;
    private final FileInfo fileInfo;
    private final Path targetPath; // Final path for the assembled file
    private Path partialFilePath; // Temporary path for the file during transfer

    private FileTransferStatus status;
    private long bytesReceived;
    // private int chunksReceived; // Replaced by BitSet cardinality for accuracy
    private OutputStream fileOutputStream;
    private final BitSet receivedChunksMask; // To track received chunks accurately

    public IncomingFileTransfer(String fileId, String senderId, FileInfo fileInfo, Path targetPath) {
        this.fileId = fileId;
        this.senderId = senderId;
        this.fileInfo = fileInfo;
        this.targetPath = targetPath;
        this.status = FileTransferStatus.AWAITING_ACCEPTANCE;
        this.bytesReceived = 0;
        // this.chunksReceived = 0;
        this.receivedChunksMask = new BitSet(fileInfo.getTotalChunks() == 0 ? 1 : fileInfo.getTotalChunks()); // Ensure BitSet has at least size 1 for empty files
        // Construct partial file path, e.g., targetPath.getParent().resolve(targetPath.getFileName() + ".part")
        if (targetPath.getParent() != null) {
            this.partialFilePath = targetPath.getParent().resolve(targetPath.getFileName().toString() + ".part");
        } else {
            this.partialFilePath = Path.of(targetPath.getFileName().toString() + ".part");
            logger.warn("Target path {} for file transfer {} does not have a parent directory. Partial file will be in current dir: {}", targetPath, fileId, this.partialFilePath.toAbsolutePath());
        }
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

    public int getChunksReceivedCount() {
        return receivedChunksMask.cardinality();
    }

    public Path getFinalFilePath() {
        return targetPath;
    }

    public boolean areAllChunksReceived() {
        if (fileInfo.getTotalChunks() == 0) {
             return getChunksReceivedCount() >= 1;
        }
        // Check if all bits from 0 to totalChunks-1 are set
        for (int i = 0; i < fileInfo.getTotalChunks(); i++) {
            if (!receivedChunksMask.get(i)) {
                return false;
            }
        }
        return true;
    }

    public synchronized void assembleFile() throws IOException {
        if (status == FileTransferStatus.RECEIVING_CHUNKS && areAllChunksReceived()) {
            closeStream();
            try {
                if (Files.exists(partialFilePath)) {
                    // Ensure target directory exists
                    if (targetPath.getParent() != null && !Files.exists(targetPath.getParent())) {
                        Files.createDirectories(targetPath.getParent());
                    }
                    Files.move(partialFilePath, targetPath);
                    setStatus(FileTransferStatus.COMPLETED);
                    logger.info("File {} assembled successfully at {}. Total bytes: {}. Chunks: {}",
                            fileId, targetPath, bytesReceived, getChunksReceivedCount());
                } else {
                    if (fileInfo.getFileSize() == 0 && areAllChunksReceived()) {
                        if (targetPath.getParent() != null && !Files.exists(targetPath.getParent())) {
                            Files.createDirectories(targetPath.getParent());
                        }
                        Files.createFile(targetPath);
                        setStatus(FileTransferStatus.COMPLETED);
                        logger.info("Empty file {} created successfully at {}.", fileId, targetPath);
                    } else {
                        logger.error("Partial file {} does not exist for assembly. File ID: {}", partialFilePath, fileId);
                        setStatus(FileTransferStatus.FAILED);
                        throw new IOException("Partial file missing for assembly: " + partialFilePath);
                    }
                }
            } catch (IOException e) {
                logger.error("Failed to move/assemble partial file {} to {}. Error: {}", partialFilePath, targetPath, e.getMessage(), e);
                setStatus(FileTransferStatus.FAILED);
                closeAndCleanupFile();
                throw e;
            }
        } else if (status != FileTransferStatus.COMPLETED) {
            logger.warn("Attempt to assemble file {} but not all chunks received or status is not RECEIVING_CHUNKS. Status: {}, Chunks: {}/{}",
                        fileId, status, getChunksReceivedCount(), fileInfo.getTotalChunks());
        }
    }

    public synchronized boolean addChunk(int chunkIndex, byte[] chunkData) throws IOException {
        if (status != FileTransferStatus.RECEIVING_CHUNKS && status != FileTransferStatus.AWAITING_CHUNKS) {
            logger.warn("Attempted to add chunk {} to transfer {} which is not in a receptive state. Status: {}", chunkIndex, fileId, status);
            return areAllChunksReceived();
        }

        // For empty files, totalChunks might be 1 (for the empty chunk signal) or 0.
        // If totalChunks is 0, chunkIndex should be 0.
        // If totalChunks is 1 (for empty file), chunkIndex should be 0.
        int expectedTotalChunks = fileInfo.getTotalChunks();
        if (expectedTotalChunks == 0) expectedTotalChunks = 1; // Treat 0 total chunks as 1 for indexing

        if (chunkIndex < 0 || chunkIndex >= expectedTotalChunks) {
             logger.warn("Received chunk with invalid index {} for file {}. Expected 0-{}. TotalChunks from FileInfo: {}. Ignoring.",
                         chunkIndex, fileId, expectedTotalChunks -1, fileInfo.getTotalChunks());
            return areAllChunksReceived();
        }

        if (fileOutputStream == null && fileInfo.getFileSize() > 0) {
            Path parentDir = partialFilePath.getParent();
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
            }
            try {
                fileOutputStream = Files.newOutputStream(partialFilePath, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                logger.info("Opened file output stream for incoming transfer {}: {}", fileId, partialFilePath);
            } catch (IOException e) {
                logger.error("Failed to create/open partial file for incoming transfer {}: {}. Error: {}", fileId, partialFilePath, e.getMessage(), e);
                setStatus(FileTransferStatus.FAILED);
                throw e;
            }
        }

        if (status == FileTransferStatus.AWAITING_CHUNKS) {
            setStatus(FileTransferStatus.RECEIVING_CHUNKS);
        }

        if (chunkData != null && chunkData.length > 0 && fileOutputStream != null) {
            fileOutputStream.write(chunkData);
            bytesReceived += chunkData.length;
        } else if ((chunkData == null || chunkData.length == 0) && fileInfo.getFileSize() == 0 && chunkIndex == 0) {
            // This is the expected empty chunk for an empty file
             logger.debug("Received the empty chunk for empty file {}", fileId);
        } else if (chunkData == null || chunkData.length == 0) {
            logger.debug("Received empty chunk data for chunk index {} in file {} (non-empty file or not first chunk of empty file).", chunkIndex, fileId);
        }


        if (!receivedChunksMask.get(chunkIndex)) {
            receivedChunksMask.set(chunkIndex);
        }

        logger.trace("Received chunk {} for file {}. Total unique chunks: {}/{}, Bytes: {}/{}",
            chunkIndex, fileId, getChunksReceivedCount(), expectedTotalChunks, bytesReceived, fileInfo.getFileSize());

        return areAllChunksReceived();
    }

    private synchronized void closeStream() {
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

    public synchronized void closeAndCleanupFile() {
        closeStream();
        // Only delete if the status indicates a failure/cancellation before completion
        if (status == FileTransferStatus.FAILED ||
            status == FileTransferStatus.CANCELLED ||
            status == FileTransferStatus.REJECTED) {
            try {
                if (Files.exists(partialFilePath)) { // Check partialFilePath for deletion
                    Files.delete(partialFilePath);
                    logger.info("Deleted partial file for transfer {}: {}", fileId, partialFilePath);
                }
            } catch (IOException e) {
                logger.error("Error deleting partial file for transfer {}: {}. Error: {}", fileId, partialFilePath, e.getMessage(), e);
            }
        }
    }
}

