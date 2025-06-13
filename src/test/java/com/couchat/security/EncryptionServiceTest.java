package com.couchat.security;

import com.couchat.auth.PasskeyAuthService; // Import PasskeyAuthService
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito; // Import Mockito
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.KeyPairGenerator; // Import KeyPairGenerator
import java.security.NoSuchAlgorithmException; // Import NoSuchAlgorithmException
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link EncryptionService}.
 */
class EncryptionServiceTest {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionServiceTest.class);
    private EncryptionService encryptionService;
    private PasskeyAuthService mockPasskeyAuthService; // Declare mock

    @BeforeEach
    void setUp() {
        mockPasskeyAuthService = Mockito.mock(PasskeyAuthService.class); // Create mock
        // Mock any necessary methods on mockPasskeyAuthService if EncryptionService calls them during construction or RSA key loading
        // For now, assuming no critical calls during construction that need specific mock responses for these tests to pass.
        encryptionService = new EncryptionService(mockPasskeyAuthService); // Pass mock to constructor
        assertNotNull(encryptionService.getLocalRsaPublicKey(), "RSA Public key should be generated on init");
        assertNotNull(encryptionService.getLocalRsaPrivateKey(), "RSA Private key should be generated on init");
        logger.info("EncryptionService initialized for test.");
    }

    @Test
    void testRsaKeyPairGeneration() {
        // KeyPair keyPair = encryptionService.generateRsaKeyPair(); // This method is private in EncryptionService
        // To test key generation robustness, we rely on the keys loaded/generated in setUp().
        // We can verify their properties.
        assertNotNull(encryptionService.getLocalRsaPublicKey(), "Local RSA Public key should not be null.");
        assertNotNull(encryptionService.getLocalRsaPrivateKey(), "Local RSA Private key should not be null.");
        assertEquals("RSA", encryptionService.getLocalRsaPublicKey().getAlgorithm(), "Public key algorithm should be RSA.");
        // Check key size (e.g. by trying to cast to RSAPublicKey and getting modulus length if needed, but usually not necessary for basic test)
        logger.info("RSA KeyPair (loaded/generated in setup) properties test passed.");
    }

    @Test
    void testAesKeyGeneration() {
        SecretKey aesKey = encryptionService.generateAesKey();
        assertNotNull(aesKey, "Generated AES Key should not be null.");
        assertEquals("AES", aesKey.getAlgorithm(), "AES key algorithm should be AES.");
        assertEquals(32, aesKey.getEncoded().length, "AES key should be 256 bits (32 bytes)."); // 256 bits = 32 bytes
        logger.info("AES Key generation test passed.");
    }

    @Test
    void testRsaEncryptionDecryption() {
        String originalData = "This is a secret message for RSA test!";
        byte[] originalBytes = originalData.getBytes(StandardCharsets.UTF_8);

        PublicKey publicKey = encryptionService.getLocalRsaPublicKey();
        String encryptedDataB64 = encryptionService.encryptWithRsaPublicKey(originalBytes, publicKey);
        assertNotNull(encryptedDataB64, "RSA encrypted data should not be null.");
        logger.debug("RSA Encrypted (Base64): {}", encryptedDataB64);

        byte[] decryptedBytes = encryptionService.decryptWithRsaPrivateKey(encryptedDataB64, encryptionService.getLocalRsaPrivateKey());
        assertNotNull(decryptedBytes, "RSA decrypted data should not be null.");
        String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(originalData, decryptedData, "Decrypted data should match original data for RSA.");
        logger.info("RSA Encryption/Decryption test passed.");
    }

    @Test
    void testAesEncryptionDecryption() {
        SecretKey aesKey = encryptionService.generateAesKey();
        assertNotNull(aesKey, "AES key must be generated for the test.");

        String originalData = "This is a secret message for AES test! It can be a bit longer.";
        byte[] originalBytes = originalData.getBytes(StandardCharsets.UTF_8);

        String encryptedDataB64 = encryptionService.encryptWithAesKey(originalBytes, aesKey);
        assertNotNull(encryptedDataB64, "AES encrypted data should not be null.");
        logger.debug("AES Encrypted (Base64): {}", encryptedDataB64);

        byte[] decryptedBytes = encryptionService.decryptWithAesKey(encryptedDataB64, aesKey);
        assertNotNull(decryptedBytes, "AES decrypted data should not be null.");
        String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(originalData, decryptedData, "Decrypted data should match original data for AES.");
        logger.info("AES Encryption/Decryption test passed.");
    }

    @Test
    void testPublicKeyStringConversion() {
        PublicKey originalPublicKey = encryptionService.getLocalRsaPublicKey();
        String publicKeyStr = encryptionService.getPublicKeyString(originalPublicKey);
        assertNotNull(publicKeyStr, "Public key string should not be null.");
        logger.debug("Public Key String: {}", publicKeyStr);

        PublicKey reconstructedPublicKey = encryptionService.getPublicKeyFromString(publicKeyStr);
        assertNotNull(reconstructedPublicKey, "Reconstructed public key should not be null.");

        assertEquals(originalPublicKey, reconstructedPublicKey, "Reconstructed public key should match original.");
        logger.info("PublicKey to String conversion test passed.");
    }

    @Test
    void testSecretKeyStringConversion() {
        SecretKey originalSecretKey = encryptionService.generateAesKey();
        assertNotNull(originalSecretKey, "AES key must be generated for string conversion test.");

        String secretKeyStr = encryptionService.getSecretKeyString(originalSecretKey);
        assertNotNull(secretKeyStr, "Secret key string should not be null.");
        logger.debug("Secret Key String: {}", secretKeyStr);

        SecretKey reconstructedSecretKey = encryptionService.getSecretKeyFromString(secretKeyStr);
        assertNotNull(reconstructedSecretKey, "Reconstructed secret key should not be null.");

        // SecretKeySpec.equals() compares the key material.
        assertEquals(originalSecretKey, reconstructedSecretKey, "Reconstructed secret key should match original.");
        logger.info("SecretKey to String conversion test passed.");
    }

    @Test
    void testRsaEncryptionWithDifferentKeyPair() throws NoSuchAlgorithmException { // Add NoSuchAlgorithmException
        // Test encryption with one keypair's public key and decryption with another's private key (should fail or be different)
        // Generate key pairs directly for this test to simulate different entities
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair1 = keyGen.generateKeyPair();
        KeyPair keyPair2 = keyGen.generateKeyPair();

        String originalData = "Test data for cross-keypair RSA.";
        byte[] originalBytes = originalData.getBytes(StandardCharsets.UTF_8);

        // Encrypt with keyPair1's public key
        String encryptedDataB64 = encryptionService.encryptWithRsaPublicKey(originalBytes, keyPair1.getPublic());
        assertNotNull(encryptedDataB64);

        // Attempt to decrypt with keyPair2's private key
        byte[] decryptedBytesWithKey2 = encryptionService.decryptWithRsaPrivateKey(encryptedDataB64, keyPair2.getPrivate());

        // If decryption "succeeds" (doesn't throw an exception like BadPaddingException immediately),
        // the result should not match the original. More often, it will throw an exception or return null.
        if (decryptedBytesWithKey2 != null) {
            String decryptedDataWithKey2 = new String(decryptedBytesWithKey2, StandardCharsets.UTF_8);
            assertNotEquals(originalData, decryptedDataWithKey2, "Decryption with a different private key should not yield the original data.");
        } else {
            // This is also an acceptable outcome (decryption failed and returned null)
            assertNull(decryptedBytesWithKey2, "Decryption with a different private key should ideally fail (return null or throw).");
        }

        // Decrypt with keyPair1's private key (should succeed)
        byte[] decryptedBytesWithKey1 = encryptionService.decryptWithRsaPrivateKey(encryptedDataB64, keyPair1.getPrivate());
        assertNotNull(decryptedBytesWithKey1);
        assertEquals(originalData, new String(decryptedBytesWithKey1, StandardCharsets.UTF_8), "Decryption with the correct private key should succeed.");
        logger.info("RSA cross-keypair decryption test (negative and positive case) passed.");
    }
}
