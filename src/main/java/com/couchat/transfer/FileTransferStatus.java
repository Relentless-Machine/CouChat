package com.couchat.transfer;

/**
 * Represents the status of a file transfer.
 */
public enum FileTransferStatus {
    /**
     * Initial state when a file transfer is offered but not yet accepted by the recipient.
     * (For outgoing transfers, after FILE_INFO is sent; for incoming, after FILE_INFO is received).
     */
    AWAITING_ACCEPTANCE,

    /**
     * State when the recipient has accepted the file transfer.
     * (For outgoing transfers, after receiving FILE_TRANSFER_ACCEPTED; for incoming, after sending FILE_TRANSFER_ACCEPTED).
     * The sender can now start sending chunks. The receiver is ready to receive chunks.
     */
    ACCEPTED, // Might not be explicitly used if AWAITING_ACCEPTANCE directly transitions to SENDING/RECEIVING

    /**
     * State when the sender is actively sending file chunks.
     */
    SENDING_CHUNKS,

    /**
     * State when the recipient is actively receiving file chunks.
     */
    RECEIVING_CHUNKS,

    /**
     * State when all file chunks have been successfully sent by the sender
     * and a completion message has been dispatched.
     * Or, when all chunks have been successfully received and assembled by the recipient.
     */
    COMPLETED,

    /**
     * State when the file transfer has been explicitly rejected by the recipient.
     */
    REJECTED,

    /**
     * State when the file transfer has been cancelled by either the sender or the recipient.
     */
    CANCELLED,

    /**
     * State when the file transfer has failed due to an error (e.g., IO error, network issue, timeout).
     */
    FAILED,

    /**
     * State when a transfer is paused (future enhancement).
     */
    PAUSED
}

