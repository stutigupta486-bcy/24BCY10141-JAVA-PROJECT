import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * CryptoUtil
 * ----------
 * Core cryptographic engine for CyberVault.
 * Implements password-based AES-256-GCM authenticated encryption with
 * PBKDF2WithHmacSHA256 key derivation (OWASP-recommended primitives).
 *
 * File format produced by encrypt():
 * [ 16 bytes salt ][ 12 bytes IV ][ ciphertext + 16-byte GCM auth tag ]
 */
public class CryptoUtil {

    public static final int SALT_LENGTH = 16;      // bytes
    public static final int IV_LENGTH = 12;         // bytes (GCM standard)
    public static final int GCM_TAG_LENGTH = 128;    // bits
    public static final int KEY_LENGTH = 256;        // bits (AES-256)
    public static final int PBKDF2_ITERATIONS = 65536;

    private CryptoUtil() {
        // utility class, no instances
    }

    /** Derives a 256-bit AES key from a password + salt using PBKDF2WithHmacSHA256. */
    public static SecretKeySpec deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /** Generates cryptographically secure random bytes of the given length. */
    public static byte[] randomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Encrypts arbitrary bytes with a password.
     * Returns: salt || iv || ciphertext(+tag)
     */
    public static byte[] encrypt(byte[] plaintext, char[] password) throws Exception {
        byte[] salt = randomBytes(SALT_LENGTH);
        byte[] iv = randomBytes(IV_LENGTH);
        SecretKeySpec key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] cipherText = cipher.doFinal(plaintext);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(salt);
        out.write(iv);
        out.write(cipherText);
        return out.toByteArray();
    }

    /**
     * Decrypts data produced by encrypt(). Throws an exception (caught by caller)
     * if the password is wrong or the data has been tampered with, because GCM
     * verifies the authentication tag before releasing any plaintext.
     */
    public static byte[] decrypt(byte[] data, char[] password) throws Exception {
        if (data.length < SALT_LENGTH + IV_LENGTH + 1) {
            throw new IllegalArgumentException("Encrypted data is too short or corrupted.");
        }
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] cipherText = new byte[data.length - SALT_LENGTH - IV_LENGTH];

        System.arraycopy(data, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(data, SALT_LENGTH, iv, 0, IV_LENGTH);
        System.arraycopy(data, SALT_LENGTH + IV_LENGTH, cipherText, 0, cipherText.length);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(cipherText);
    }

    /** Convenience method: encrypts an entire file to a destination file. */
    public static void encryptFile(File input, File output, char[] password) throws Exception {
        byte[] plain = readAllBytes(input);
        byte[] encrypted = encrypt(plain, password);
        writeAllBytes(output, encrypted);
    }

    /** Convenience method: decrypts an entire file to a destination file. */
    public static void decryptFile(File input, File output, char[] password) throws Exception {
        byte[] encrypted = readAllBytes(input);
        byte[] plain = decrypt(encrypted, password);
        writeAllBytes(output, plain);
    }

    private static byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, read);
            }
            return bos.toByteArray();
        }
    }

    private static void writeAllBytes(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}