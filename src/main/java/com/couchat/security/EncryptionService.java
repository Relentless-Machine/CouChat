// filepath: F:/Git/CouChat/src/main/java/com/couchat/security/EncryptionService.java
package com.couchat.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding"; // Or AES/GCM/NoPadding for more security
    private static final int AES_KEY_SIZE = 256; // Or 128, 192

    private KeyPair localRsaKeyPair;

    public EncryptionService() {
        try {
            this.localRsaKeyPair = generateRsaKeyPair();
            logger.info("EncryptionService initialized with new RSA key pair.");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to generate RSA key pair on initialization.", e);
            // Handle error appropriately, maybe throw a runtime exception
            throw new RuntimeException("Failed to initialize EncryptionService due to RSA key generation failure", e);
        }
    }

    public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // 2048-bit RSA keys
        return keyGen.generateKeyPair();
    }

    public PublicKey getLocalRsaPublicKey() {
        return localRsaKeyPair != null ? localRsaKeyPair.getPublic() : null;
    }

    public PrivateKey getLocalRsaPrivateKey() {
        return localRsaKeyPair != null ? localRsaKeyPair.getPrivate() : null;
    }

    public String getPublicKeyString(PublicKey publicKey) {
        if (publicKey == null) return null;
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public PublicKey getPublicKeyFromString(String keyString) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            logger.error("Error converting string to PublicKey: {}", e.getMessage(), e);
            return null;
        }
    }

    public byte[] encryptWithRsaPublicKey(byte[] data, PublicKey publicKey) {
        if (data == null || publicKey == null) {
            logger.warn("RSA encryption failed: data or public key is null.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            logger.error("Error encrypting with RSA public key: {}", e.getMessage(), e);
            return null;
        }
    }

    public byte[] decryptWithRsaPrivateKey(byte[] encryptedData) {
        if (encryptedData == null || getLocalRsaPrivateKey() == null) {
            logger.warn("RSA decryption failed: encrypted data or local private key is null.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getLocalRsaPrivateKey());
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            logger.error("Error decrypting with RSA private key: {}", e.getMessage(), e);
            return null;
        }
    }

    public SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    public SecretKey getAesKeyFromBytes(byte[] keyBytes) {
        if (keyBytes == null) {
            logger.warn("Cannot create AES key from null bytes.");
            return null;
        }
        // AES_KEY_SIZE is in bits, so divide by 8 for bytes
        if (keyBytes.length != AES_KEY_SIZE / 8) {
            logger.warn("Invalid AES key length: {} bytes. Expected {} bytes for AES-{}.",
                        keyBytes.length, AES_KEY_SIZE / 8, AES_KEY_SIZE);
            // Consider throwing an IllegalArgumentException for critical errors
            return null;
        }
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    public String encryptWithAesKey(byte[] data, SecretKey aesKey) {
        if (data == null || aesKey == null) {
            logger.warn("AES encryption failed: data or AES key is null.");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedBytes = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            logger.error("Error encrypting with AES key: {}", e.getMessage(), e);
            return null;
        }
    }

    public byte[] decryptWithAesKey(String encryptedDataB64, SecretKey aesKey) {
        if (encryptedDataB64 == null || aesKey == null) {
            logger.warn("AES decryption failed: encrypted data or AES key is null.");
            return null;
        }
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedDataB64);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return cipher.doFinal(encryptedBytes);
        } catch (Exception e) {
            logger.error("Error decrypting with AES key: {}", e.getMessage(), e);
            return null;
        }
    }
}

