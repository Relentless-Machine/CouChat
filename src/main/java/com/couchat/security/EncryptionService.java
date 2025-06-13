package com.couchat.security;

import com.couchat.auth.PasskeyAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
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
    // Changed AES_TRANSFORMATION to GCM mode
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private static final int GCM_IV_LENGTH_BYTES = 12; // Standard IV length for GCM
    private static final int GCM_TAG_LENGTH_BITS = 128; // Standard tag length for GCM

    private static final String CONFIG_DIR_NAME = ".couchat";
    private static final String RSA_PUBLIC_KEY_FILE = "rsa.pub";
    private static final String RSA_PRIVATE_KEY_FILE = "rsa.key";

    private final PasskeyAuthService passkeyAuthService; // For potential future use (e.g., encrypting stored keys)

    private KeyPair localRsaKeyPair;

    /**
     * Constructs the EncryptionService.
     *
     * @param passkeyAuthService Service to get authentication details, potentially for key protection.
     */
    public EncryptionService(PasskeyAuthService passkeyAuthService) {
        this.passkeyAuthService = passkeyAuthService;
        loadOrGenerateRsaKeyPair();
    }

    private void loadOrGenerateRsaKeyPair() {
        File configDir = new File(System.getProperty("user.home"), CONFIG_DIR_NAME);
        File publicKeyFile = new File(configDir, RSA_PUBLIC_KEY_FILE);
        File privateKeyFile = new File(configDir, RSA_PRIVATE_KEY_FILE);

        if (publicKeyFile.exists() && privateKeyFile.exists()) {
            try {
                byte[] publicKeyBytes = java.nio.file.Files.readAllBytes(publicKeyFile.toPath());
                byte[] privateKeyBytes = java.nio.file.Files.readAllBytes(privateKeyFile.toPath());

                KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

                this.localRsaKeyPair = new KeyPair(publicKey, privateKey);
                logger.info("RSA key pair loaded successfully from {} and {}.", publicKeyFile.getAbsolutePath(), privateKeyFile.getAbsolutePath());
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                logger.error("Failed to load RSA key pair from files. Generating a new one.", e);
                generateAndStoreRsaKeyPair(publicKeyFile, privateKeyFile, configDir);
            }
        } else {
            logger.info("RSA key pair not found. Generating a new one.");
            generateAndStoreRsaKeyPair(publicKeyFile, privateKeyFile, configDir);
        }

        if (this.localRsaKeyPair == null) {
            logger.error("CRITICAL: RSA key pair is null after attempting load/generation. Encryption service will not function correctly.");
        }
    }

    private void generateAndStoreRsaKeyPair(File publicKeyFile, File privateKeyFile, File configDir) {
        this.localRsaKeyPair = generateRsaKeyPairInternal();
        if (this.localRsaKeyPair != null) {
            logger.info("New RSA key pair generated for local user.");
            try {
                if (!configDir.exists()) {
                    if (configDir.mkdirs()) {
                        logger.info("Created configuration directory: {}", configDir.getAbsolutePath());
                    } else {
                        logger.error("Failed to create configuration directory: {}. RSA keys will not be persisted.", configDir.getAbsolutePath());
                        return; // Cannot store keys
                    }
                }
                java.nio.file.Files.write(publicKeyFile.toPath(), this.localRsaKeyPair.getPublic().getEncoded());
                java.nio.file.Files.write(privateKeyFile.toPath(), this.localRsaKeyPair.getPrivate().getEncoded());
                logger.info("RSA key pair stored successfully to {} and {}.", publicKeyFile.getAbsolutePath(), privateKeyFile.getAbsolutePath());
            } catch (IOException e) {
                logger.error("Failed to store RSA key pair. Keys will be in-memory for this session.", e);
            }
        } else {
            logger.error("Failed to generate RSA key pair during store operation.");
        }
    }

    /**
     * Internal RSA key pair generation logic.
     */
    private KeyPair generateRsaKeyPairInternal() {
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
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SecureRandom random = SecureRandom.getInstanceStrong(); // Use a strong RNG for IV
            random.nextBytes(iv);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            byte[] encryptedBytes = cipher.doFinal(data);

            // Concatenate IV and ciphertext: IV + Ciphertext
            byte[] ivAndEncryptedBytes = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, ivAndEncryptedBytes, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, ivAndEncryptedBytes, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(ivAndEncryptedBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("AES encryption algorithm/padding GCM not found or SecureRandom issue.", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            logger.error("Invalid AES key or GCM parameters for encryption.", e);
        } catch (Exception e) { // General exception for doFinal (e.g., IllegalBlockSizeException)
            logger.error("Error during AES encryption with GCM.", e);
        }
        return null;
    }

    /**
     * Decrypts data using an AES symmetric key with GCM mode.
     * Expects the input to be Base64 encoded (IV + Ciphertext).
     *
     * @param encryptedDataB64 The Base64 encoded (IV + Ciphertext).
     * @param secretKey The AES {@link SecretKey} to use for decryption.
     * @return The decrypted data as a byte array, or null on failure.
     */
    public byte[] decryptWithAesKey(String encryptedDataB64, SecretKey secretKey) {
        if (encryptedDataB64 == null || secretKey == null) {
            logger.warn("Encrypted data or secret key is null for AES decryption.");
            return null;
        }
        try {
            byte[] ivAndEncryptedBytes = Base64.getDecoder().decode(encryptedDataB64);

            if (ivAndEncryptedBytes.length < GCM_IV_LENGTH_BYTES) {
                logger.error("Encrypted data is too short to contain IV for GCM decryption.");
                return null;
            }

            // Extract IV from the beginning of the byte array
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            System.arraycopy(ivAndEncryptedBytes, 0, iv, 0, iv.length);

            // Extract actual ciphertext
            byte[] encryptedBytes = new byte[ivAndEncryptedBytes.length - GCM_IV_LENGTH_BYTES];
            System.arraycopy(ivAndEncryptedBytes, GCM_IV_LENGTH_BYTES, encryptedBytes, 0, encryptedBytes.length);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            return cipher.doFinal(encryptedBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.error("AES decryption algorithm/padding GCM not found.", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            logger.error("Invalid AES key or GCM parameters for decryption.", e);
        } catch (Exception e) { // General exception for doFinal (e.g., BadPaddingException, AEADBadTagException)
            logger.error("Error during AES decryption with GCM (e.g., tag mismatch).", e);
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
