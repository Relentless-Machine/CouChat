package com.couchat.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Service responsible for cryptographic operations.
 * This includes generating RSA and AES keys, encrypting and decrypting data,
 * and managing key storage and retrieval (though key persistence is not fully implemented here yet).
 */
@Service
public class EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding"; // Consider more secure modes like CBC or GCM
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"; // Standard RSA padding

    private KeyPair localRsaKeyPair; // Stores the local user's RSA key pair

    /**
     * Initializes the EncryptionService.
     * Generates a new RSA key pair for the local user upon startup if one doesn't exist.
     * In a real application, this key pair would typically be loaded from secure storage
     * or generated once and stored.
     */
    public EncryptionService() {
        // For demonstration, always generate a new RSA key pair on startup.
        // In a real app, load existing keys or generate and store them securely.
        this.localRsaKeyPair = generateRsaKeyPair();
        if (this.localRsaKeyPair != null) {
            logger.info("New RSA key pair generated for local user.");
            // logger.info("Public Key: {}", getPublicKeyString(this.localRsaKeyPair.getPublic()));
        } else {
            logger.error("Failed to generate RSA key pair on service initialization.");
            // This is a critical failure, application might not function securely.
        }
    }

    /**
     * Generates a new RSA key pair.
     *
     * @return A {@link KeyPair} containing the public and private RSA keys, or null on failure.
     */
    public KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(2048); // 2048-bit key size for good security
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            logger.debug("RSA KeyPair generated successfully.");
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            logger.error("RSA algorithm not found while generating key pair.", e);
            return null;
        }
    }

    /**
     * Generates a new AES symmetric key.
     *
     * @return A {@link SecretKey} for AES encryption, or null on failure.
     */
    public SecretKey generateAesKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGenerator.init(256); // 256-bit AES key
            SecretKey secretKey = keyGenerator.generateKey();
            logger.debug("AES Key generated successfully.");
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            logger.error("AES algorithm not found while generating key.", e);
            return null;
        }
    }

    /**
     * Encrypts data using an RSA public key.
     * Typically used to encrypt a symmetric key (like an AES key) for secure exchange.
     *
     * @param data The plaintext data to encrypt.
     * @param publicKey The RSA {@link PublicKey} to use for encryption.
     * @return The Base64 encoded encrypted data as a String, or null on failure.
     */
    public String encryptWithRsaPublicKey(byte[] data, PublicKey publicKey) {
        if (data == null || publicKey == null) {
            logger.warn("Data or public key is null for RSA encryption.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("RSA encryption algorithm or padding not found.", e);
        } catch (InvalidKeyException e) {
            logger.error("Invalid RSA public key for encryption.", e);
        } catch (Exception e) { // General exception for doFinal (e.g., IllegalBlockSizeException)
            logger.error("Error during RSA encryption.", e);
        }
        return null;
    }

    /**
     * Decrypts data using an RSA private key.
     * Typically used to decrypt a symmetric key (like an AES key) that was encrypted with the corresponding public key.
     *
     * @param encryptedDataB64 The Base64 encoded encrypted data.
     * @param privateKey The RSA {@link PrivateKey} to use for decryption.
     * @return The decrypted data as a byte array, or null on failure.
     */
    public byte[] decryptWithRsaPrivateKey(String encryptedDataB64, PrivateKey privateKey) {
        if (encryptedDataB64 == null || privateKey == null) {
            logger.warn("Encrypted data or private key is null for RSA decryption.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedDataB64);
            return cipher.doFinal(encryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("RSA decryption algorithm or padding not found.", e);
        } catch (InvalidKeyException e) {
            logger.error("Invalid RSA private key for decryption.", e);
        } catch (Exception e) { // General exception for doFinal (e.g., BadPaddingException)
            logger.error("Error during RSA decryption.", e);
        }
        return null;
    }

    /**
     * Encrypts data using an AES symmetric key.
     *
     * @param data The plaintext data to encrypt.
     * @param secretKey The AES {@link SecretKey} to use for encryption.
     * @return The Base64 encoded encrypted data as a String, or null on failure.
     */
    public String encryptWithAesKey(byte[] data, SecretKey secretKey) {
        if (data == null || secretKey == null) {
            logger.warn("Data or secret key is null for AES encryption.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("AES encryption algorithm or padding not found.", e);
        } catch (InvalidKeyException e) {
            logger.error("Invalid AES key for encryption.", e);
        } catch (Exception e) {
            logger.error("Error during AES encryption.", e);
        }
        return null;
    }

    /**
     * Decrypts data using an AES symmetric key.
     *
     * @param encryptedDataB64 The Base64 encoded encrypted data.
     * @param secretKey The AES {@link SecretKey} to use for decryption.
     * @return The decrypted data as a byte array, or null on failure.
     */
    public byte[] decryptWithAesKey(String encryptedDataB64, SecretKey secretKey) {
        if (encryptedDataB64 == null || secretKey == null) {
            logger.warn("Encrypted data or secret key is null for AES decryption.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedDataB64);
            return cipher.doFinal(encryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("AES decryption algorithm or padding not found.", e);
        } catch (InvalidKeyException e) {
            logger.error("Invalid AES key for decryption.", e);
        } catch (Exception e) {
            logger.error("Error during AES decryption.", e);
        }
        return null;
    }

    /**
     * Gets the local user's RSA public key.
     *
     * @return The {@link PublicKey}, or null if not initialized.
     */
    public PublicKey getLocalRsaPublicKey() {
        return (this.localRsaKeyPair != null) ? this.localRsaKeyPair.getPublic() : null;
    }

    /**
     * Gets the local user's RSA private key.
     *
     * @return The {@link PrivateKey}, or null if not initialized.
     */
    public PrivateKey getLocalRsaPrivateKey() {
        return (this.localRsaKeyPair != null) ? this.localRsaKeyPair.getPrivate() : null;
    }

    /**
     * Converts a PublicKey to its Base64 encoded string representation.
     *
     * @param publicKey The PublicKey to convert.
     * @return Base64 encoded string of the public key, or null if input is null.
     */
    public String getPublicKeyString(PublicKey publicKey) {
        if (publicKey == null) return null;
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Converts a Base64 encoded string representation of a public key back to a PublicKey object.
     *
     * @param publicKeyString The Base64 encoded public key string.
     * @return {@link PublicKey} object, or null on failure.
     */
    public PublicKey getPublicKeyFromString(String publicKeyString) {
        if (publicKeyString == null) return null;
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Error reconstructing public key from string.", e);
            return null;
        }
    }

    /**
     * Converts a SecretKey to its Base64 encoded string representation.
     *
     * @param secretKey The SecretKey to convert.
     * @return Base64 encoded string of the secret key, or null if input is null.
     */
    public String getSecretKeyString(SecretKey secretKey) {
        if (secretKey == null) return null;
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * Converts a Base64 encoded string representation of an AES secret key back to a SecretKey object.
     *
     * @param secretKeyString The Base64 encoded secret key string.
     * @return {@link SecretKey} object for AES, or null on failure.
     */
    public SecretKey getSecretKeyFromString(String secretKeyString) {
        if (secretKeyString == null) return null;
        try {
            byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
            return new SecretKeySpec(decodedKey, 0, decodedKey.length, AES_ALGORITHM);
        } catch (IllegalArgumentException e) {
            logger.error("Error reconstructing secret key from string (e.g., invalid key length).", e);
            return null;
        }
    }
}

