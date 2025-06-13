package com.couchat.repository;

import com.couchat.transfer.model.FileTransfer;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for {@link FileTransfer} entities.
 * Defines a contract for data access operations related to file transfers.
 */
public interface FileTransferRepository {

    /**
     * Saves a new file transfer record or updates an existing one.
     *
     * @param fileTransfer The {@link FileTransfer} object to save. Must not be null.
     * @return The saved {@link FileTransfer} object.
     */
    FileTransfer save(FileTransfer fileTransfer);

    /**
     * Finds a file transfer record by its unique ID.
     *
     * @param fileId The ID of the file transfer to find. Must not be null.
     * @return An {@link Optional} containing the {@link FileTransfer} if found, or an empty Optional otherwise.
     */
    Optional<FileTransfer> findById(String fileId);

    /**
     * Finds a file transfer record by the ID of the message that initiated it.
     *
     * @param messageId The ID of the initiating message. Must not be null.
     * @return An {@link Optional} containing the {@link FileTransfer} if found.
     */
    Optional<FileTransfer> findByMessageId(String messageId);

    /**
     * Retrieves all file transfer records with a specific status.
     *
     * @param status The {@link FileTransfer.FileTransferStatus} to filter by. Must not be null.
     * @return A list of {@link FileTransfer} objects matching the status.
     */
    List<FileTransfer> findByStatus(FileTransfer.FileTransferStatus status);

    /**
     * Retrieves all file transfers initiated by a specific sender.
     *
     * @param senderId The ID of the sender. Must not be null.
     * @return A list of {@link FileTransfer} objects.
     */
    List<FileTransfer> findBySenderId(String senderId); // Assuming senderId is on FileTransfer or Message

    /**
     * Retrieves all file transfers targeted at a specific recipient.
     *
     * @param recipientId The ID of the recipient. Must not be null.
     * @return A list of {@link FileTransfer} objects.
     */
    List<FileTransfer> findByRecipientId(String recipientId); // Assuming recipientId is on FileTransfer or Message

    /**
     * Updates the status of a file transfer.
     *
     * @param fileId The ID of the file transfer to update. Must not be null.
     * @param newStatus The new {@link FileTransfer.FileTransferStatus}. Must not be null.
     * @return true if the status was updated successfully, false otherwise.
     */
    boolean updateStatus(String fileId, FileTransfer.FileTransferStatus newStatus);

    /**
     * Updates the local path of a downloaded file for a file transfer.
     *
     * @param fileId The ID of the file transfer. Must not be null.
     * @param localPath The new local path of the file. Must not be null.
     * @return true if the path was updated successfully, false otherwise.
     */
    boolean updateLocalPath(String fileId, String localPath);

    /**
     * Updates the hash value of a file transfer.
     *
     * @param fileId The ID of the file transfer. Must not be null.
     * @param hashValue The new hash value. Must not be null.
     * @return true if the hash value was updated successfully, false otherwise.
     */
    boolean updateHashValue(String fileId, String hashValue);

    /**
     * Deletes a file transfer record by its ID.
     *
     * @param fileId The ID of the file transfer record to delete. Must not be null.
     * @return true if the record was deleted successfully, false otherwise.
     */
    boolean deleteById(String fileId);
}

