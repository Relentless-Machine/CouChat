// filepath: F:/Git/CouChat/src/main/java/com/couchat/transfer/FileTransferStatus.java
package com.couchat.transfer;

public enum FileTransferStatus {
    PENDING,                // Transfer initiated, awaiting metadata exchange or initial handshake
    AWAITING_ACCEPTANCE,    // FileInfo sent, waiting for recipient to accept/reject
    ACCEPTED,               // Recipient accepted, sender can start sending chunks
    SENDING_CHUNKS,         // Sender is actively sending chunks
    RECEIVING_CHUNKS,       // Recipient is actively receiving chunks
    AWAITING_CHUNKS,        // Recipient has accepted and is ready, but first chunk not yet received
    COMPLETED,              // All chunks sent/received, file assembled successfully
    FAILED,                 // Transfer failed due to an error
    REJECTED,               // Recipient rejected the transfer
    CANCELLED               // Transfer cancelled by sender or recipient
}

