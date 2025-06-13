package com.couchat.repository.impl;

import com.couchat.repository.FileTransferRepository;
import com.couchat.transfer.model.FileTransfer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * JDBC implementation of the {@link FileTransferRepository} interface.
 * Provides stub or minimal implementations for now to allow application context to load.
 */
@Repository
public class JdbcFileTransferRepository implements FileTransferRepository {

    private static final Logger logger = LoggerFactory.getLogger(JdbcFileTransferRepository.class);
    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<FileTransfer> fileTransferRowMapper = (rs, rowNum) -> new FileTransfer(
            rs.getString("file_id"),
            rs.getString("message_id"),
            rs.getString("file_name"),
            rs.getLong("file_size"),
            rs.getString("mime_type"),
            rs.getString("local_path"),
            FileTransfer.FileTransferStatus.valueOf(rs.getString("status")),
            rs.getString("hash_value"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant()
    );

    @Autowired
    public JdbcFileTransferRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public FileTransfer save(FileTransfer fileTransfer) {
        logger.info("JdbcFileTransferRepository.save called for fileId: {}", fileTransfer.getFileId());
        if (fileTransfer == null) {
            throw new IllegalArgumentException("FileTransfer to save cannot be null.");
        }
        String sql = "INSERT INTO file_transfers (file_id, message_id, file_name, file_size, mime_type, local_path, " +
                     "status, hash_value, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(file_id) DO UPDATE SET " +
                     "message_id = excluded.message_id, " +
                     "file_name = excluded.file_name, " +
                     "file_size = excluded.file_size, " +
                     "mime_type = excluded.mime_type, " +
                     "local_path = excluded.local_path, " +
                     "status = excluded.status, " +
                     "hash_value = excluded.hash_value, " +
                     "updated_at = excluded.updated_at";
        try {
            jdbcTemplate.update(sql,
                    fileTransfer.getFileId(),
                    fileTransfer.getMessageId(),
                    fileTransfer.getFileName(),
                    fileTransfer.getFileSize(),
                    fileTransfer.getMimeType(),
                    fileTransfer.getLocalPath(),
                    fileTransfer.getStatus().name(),
                    fileTransfer.getHashValue(),
                    Timestamp.from(fileTransfer.getCreatedAt()),
                    Timestamp.from(fileTransfer.getUpdatedAt())
            );
            return fileTransfer;
        } catch (DataAccessException e) {
            logger.error("Error saving fileTransfer with ID {}: {}", fileTransfer.getFileId(), e.getMessage(), e);
            throw new RuntimeException("Failed to save fileTransfer", e);
        }
    }

    @Override
    public Optional<FileTransfer> findById(String fileId) {
        logger.info("JdbcFileTransferRepository.findById called for fileId: {}", fileId);
        if (fileId == null) return Optional.empty();
        String sql = "SELECT * FROM file_transfers WHERE file_id = ?";
        try {
            FileTransfer ft = jdbcTemplate.queryForObject(sql, new Object[]{fileId}, fileTransferRowMapper);
            return Optional.ofNullable(ft);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding fileTransfer by ID {}: {}", fileId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<FileTransfer> findByMessageId(String messageId) {
        logger.info("JdbcFileTransferRepository.findByMessageId called for messageId: {}", messageId);
        if (messageId == null) return Optional.empty();
        String sql = "SELECT * FROM file_transfers WHERE message_id = ?";
        try {
            FileTransfer ft = jdbcTemplate.queryForObject(sql, new Object[]{messageId}, fileTransferRowMapper);
            return Optional.ofNullable(ft);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            logger.error("Error finding fileTransfer by message ID {}: {}", messageId, e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    public List<FileTransfer> findByStatus(FileTransfer.FileTransferStatus status) {
        logger.info("JdbcFileTransferRepository.findByStatus called for status: {}", status);
        if (status == null) return Collections.emptyList();
        String sql = "SELECT * FROM file_transfers WHERE status = ? ORDER BY created_at DESC";
        try {
            return jdbcTemplate.query(sql, new Object[]{status.name()}, fileTransferRowMapper);
        } catch (DataAccessException e) {
            logger.error("Error finding fileTransfers by status {}: {}", status, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public List<FileTransfer> findBySenderId(String senderId) {
        logger.info("JdbcFileTransferRepository.findBySenderId called for senderId: {}. This is a STUB.", senderId);
        // This requires joining with messages table to get sender_id
        // SELECT ft.* FROM file_transfers ft JOIN messages m ON ft.message_id = m.message_id WHERE m.sender_id = ?
        // For now, returning empty list as a stub.
        return Collections.emptyList();
    }

    @Override
    public List<FileTransfer> findByRecipientId(String recipientId) {
        logger.info("JdbcFileTransferRepository.findByRecipientId called for recipientId: {}. This is a STUB.", recipientId);
        // This requires joining with messages and potentially conversations to determine recipient
        // For now, returning empty list as a stub.
        return Collections.emptyList();
    }

    @Override
    public boolean updateStatus(String fileId, FileTransfer.FileTransferStatus newStatus) {
        logger.info("JdbcFileTransferRepository.updateStatus called for fileId: {}, newStatus: {}", fileId, newStatus);
        if (fileId == null || newStatus == null) return false;
        String sql = "UPDATE file_transfers SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE file_id = ?";
        try {
            return jdbcTemplate.update(sql, newStatus.name(), fileId) > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating status for fileTransfer ID {}: {}", fileId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateLocalPath(String fileId, String localPath) {
        logger.info("JdbcFileTransferRepository.updateLocalPath called for fileId: {}, localPath: {}", fileId, localPath);
        if (fileId == null || localPath == null) return false;
        String sql = "UPDATE file_transfers SET local_path = ?, updated_at = CURRENT_TIMESTAMP WHERE file_id = ?";
        try {
            return jdbcTemplate.update(sql, localPath, fileId) > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating local_path for fileTransfer ID {}: {}", fileId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean updateHashValue(String fileId, String hashValue) {
        logger.info("JdbcFileTransferRepository.updateHashValue called for fileId: {}, hashValue: {}", fileId, hashValue);
        if (fileId == null || hashValue == null) return false;
        String sql = "UPDATE file_transfers SET hash_value = ?, updated_at = CURRENT_TIMESTAMP WHERE file_id = ?";
        try {
            return jdbcTemplate.update(sql, hashValue, fileId) > 0;
        } catch (DataAccessException e) {
            logger.error("Error updating hash_value for fileTransfer ID {}: {}", fileId, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean deleteById(String fileId) {
        logger.info("JdbcFileTransferRepository.deleteById called for fileId: {}", fileId);
        if (fileId == null) return false;
        String sql = "DELETE FROM file_transfers WHERE file_id = ?";
        try {
            return jdbcTemplate.update(sql, fileId) > 0;
        } catch (DataAccessException e) {
            logger.error("Error deleting fileTransfer by ID {}: {}", fileId, e.getMessage(), e);
            return false;
        }
    }
}


