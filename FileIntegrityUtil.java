import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * FileIntegrityUtil
 * -----------------
 * Computes and verifies SHA-256 checksums so a user can detect whether a file
 * has been altered (accidentally or maliciously) since it was last hashed.
 */
public class FileIntegrityUtil {

    private FileIntegrityUtil() {
    }

    /** Computes the SHA-256 hash of a file and returns it as a lowercase hex string. */
    public static String computeSHA256(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        return bytesToHex(digest.digest());
    }

    /** Writes a "<filename>.sha256" file next to the given file containing its checksum. */
    public static File generateChecksumFile(File file) throws IOException, NoSuchAlgorithmException {
        String hash = computeSHA256(file);
        File checksumFile = new File(file.getAbsolutePath() + ".sha256");
        try (FileWriter writer = new FileWriter(checksumFile)) {
            writer.write(hash + "  " + file.getName());
        }
        return checksumFile;
    }

    /** Verifies that a file's current SHA-256 hash matches an expected hash (case-insensitive). */
    public static boolean verify(File file, String expectedHash) throws IOException, NoSuchAlgorithmException {
        String actual = computeSHA256(file);
        return actual.equalsIgnoreCase(expectedHash.trim());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}