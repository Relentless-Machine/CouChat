package com.couchat.security;

import com.couchat.auth.PasskeyAuthService; // Import PasskeyAuthService
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito; // Import Mockito
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec; // Added import
import javax.crypto.Cipher; // Added import
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
        // mockPasskeyAuthService = Mockito.mock(PasskeyAuthService.class); // No longer needed for constructor
        encryptionService = new EncryptionService(); // Use no-arg constructor
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
    void testAesKeyGeneration() throws NoSuchAlgorithmException { // Added throws declaration
        SecretKey aesKey = encryptionService.generateAesKey();
        assertNotNull(aesKey, "Generated AES Key should not be null.");
        assertEquals("AES", aesKey.getAlgorithm(), "AES key algorithm should be AES.");
        assertEquals(32, aesKey.getEncoded().length, "AES key should be 256 bits (32 bytes)."); // 256 bits = 32 bytes
        logger.info("AES Key generation test passed.");
    }

    @Test
    void testRsaEncryptionDecryption() throws NoSuchAlgorithmException { // Added throws declaration
        String originalData = "This is a secret message for RSA test!";
        byte[] originalBytes = originalData.getBytes(StandardCharsets.UTF_8);

        PublicKey publicKey = encryptionService.getLocalRsaPublicKey();
        // encryptWithRsaPublicKey now returns byte[]
        byte[] encryptedDataBytes = encryptionService.encryptWithRsaPublicKey(originalBytes, publicKey);
        assertNotNull(encryptedDataBytes, "RSA encrypted data should not be null.");
        String encryptedDataB64 = Base64.getEncoder().encodeToString(encryptedDataBytes); // Manually encode for logging or if needed elsewhere
        logger.debug("RSA Encrypted (Base64): {}", encryptedDataB64);

        // decryptWithRsaPrivateKey now takes byte[] (the raw encrypted data)
        byte[] decryptedBytes = encryptionService.decryptWithRsaPrivateKey(encryptedDataBytes); // Pass byte[] directly
        assertNotNull(decryptedBytes, "RSA decrypted data should not be null.");
        String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(originalData, decryptedData, "Decrypted data should match original data for RSA.");
        logger.info("RSA Encryption/Decryption test passed.");
    }

    @Test
    void testAesEncryptionDecryption() throws NoSuchAlgorithmException { // Added throws declaration
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
    void testSecretKeyStringConversion() throws NoSuchAlgorithmException { // Added throws declaration
        SecretKey originalSecretKey = encryptionService.generateAesKey();
        assertNotNull(originalSecretKey, "AES key must be generated for string conversion test.");

        // Manually convert SecretKey to Base64 String
        String secretKeyStr = Base64.getEncoder().encodeToString(originalSecretKey.getEncoded());
        assertNotNull(secretKeyStr, "Secret key string should not be null.");
        logger.debug("Secret Key String: {}", secretKeyStr);

        // Manually convert Base64 String back to SecretKey
        byte[] decodedKeyBytes = Base64.getDecoder().decode(secretKeyStr);
        SecretKey reconstructedSecretKey = new SecretKeySpec(decodedKeyBytes, 0, decodedKeyBytes.length, "AES");
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
        byte[] encryptedDataBytes = encryptionService.encryptWithRsaPublicKey(originalBytes, keyPair1.getPublic());
        assertNotNull(encryptedDataBytes);
        // String encryptedDataB64 = Base64.getEncoder().encodeToString(encryptedDataBytes); // For debugging or if needed

        // Attempt to decrypt with keyPair2's private key
        // Note: decryptWithRsaPrivateKey in EncryptionService uses its own localRsaKeyPair.
        // To test with keyPair2.getPrivate(), we would need a version of decryptWithRsaPrivateKey
        // that accepts a PrivateKey argument, or we need to set keyPair2 as the local keypair,
        // which is not ideal for this specific test's intent.
        // For now, this test will effectively test if data encrypted with an external public key
        // can be decrypted by the service's *own* private key (it should fail).

        // To truly test decryption with keyPair2.getPrivate(), we'd call a hypothetical
        // encryptionService.decryptWithRsaPrivateKey(encryptedDataBytes, keyPair2.getPrivate());
        // Since that method doesn't exist with that signature, we'll adapt the test's meaning slightly.
        // The current EncryptionService.decryptWithRsaPrivateKey uses its internally held private key.
        // So, if we encrypt with keyPair1.getPublic(), trying to decrypt with the service's
        // (potentially different) private key should fail if keyPair1 is not the service's keypair.

        // Let's assume the service's key is keyPairInternal.
        // If keyPair1.getPublic() is used for encryption, and the service's internal private key is keyPairInternal.getPrivate(),
        // decryption will only work if keyPair1 and keyPairInternal are the same.

        // This test needs to be re-thought if the goal is to test decrypting with an arbitrary private key.
        // Given the current EncryptionService API, we can test:
        // 1. Encrypt with service's public key, decrypt with service's private key (done in testRsaEncryptionDecryption).
        // 2. Encrypt with an external public key (keyPair1.getPublic()), try to decrypt with service's private key.
        //    This should fail if keyPair1 is different from the service's key.

        // Re-scoping the test: Encrypt with an external public key, attempt decryption with the service's private key.
        byte[] decryptedBytesWithServiceKey = encryptionService.decryptWithRsaPrivateKey(encryptedDataBytes);

        if (decryptedBytesWithServiceKey != null) {
            String decryptedDataWithServiceKey = new String(decryptedBytesWithServiceKey, StandardCharsets.UTF_8);
            // This assertion is tricky because we don't know if keyPair1 is the same as the service's internal key.
            // A better test would be to encrypt with keyPair1.getPublic() and then try to decrypt with keyPair2.getPrivate()
            // using a direct call to a static helper or a differently designed service method.
            // For now, we'll assert that it *doesn't* match if the keys are truly different.
            // This test is a bit weak due to the fixed private key in decryptWithRsaPrivateKey.
            // A more robust test would involve mocking or a different service design.
            // logger.warn("RSA cross-keypair test is limited by EncryptionService.decryptWithRsaPrivateKey using only its own key.");
             assertNotEquals(originalData, decryptedDataWithServiceKey, "Decryption with the service's private key should not yield original data if encrypted with a truly different public key.");
        } else {
            assertNull(decryptedBytesWithServiceKey, "Decryption with service's key should fail (return null) if encrypted with a different public key.");
        }


        // Decrypt with keyPair1's private key (should succeed, but we need a method for this)
        // byte[] decryptedBytesWithKey1 = encryptionService.decryptWithRsaPrivateKey(encryptedDataB64, keyPair1.getPrivate());
        // To do this properly, we'd need a static helper or a method in EncryptionService that takes a PrivateKey.
        // For now, we'll use Cipher directly to verify the encrypted data if we had keyPair1.getPrivate().
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair1.getPrivate());
            byte[] directlyDecryptedBytes = cipher.doFinal(encryptedDataBytes);
            assertEquals(originalData, new String(directlyDecryptedBytes, StandardCharsets.UTF_8), "Direct decryption with the correct private key (keyPair1.getPrivate()) should succeed.");
        } catch (Exception e) {
            fail("Decryption with keyPair1's private key failed unexpectedly: " + e.getMessage());
        }
        logger.info("RSA cross-keypair decryption test (adapted) passed.");
    }
}
