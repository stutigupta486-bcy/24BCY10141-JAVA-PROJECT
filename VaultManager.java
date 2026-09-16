import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.AEADBadTagException;

/**
 * VaultManager
 * ------------
 * A minimal, self-contained encrypted password manager. All credential
 * entries are held in memory only while unlocked, serialized to a single
 * text blob, and encrypted as a whole with the master password via
 * CryptoUtil (AES-256-GCM + PBKDF2). Nothing is ever written to disk in
 * plaintext.
 *
 * Field delimiter: \u0001 (unlikely to appear in normal text)
 * Record delimiter: \n
 */
public class VaultManager {

    private static final String FIELD_SEP = "\u0001";
    private static final File VAULT_FILE = new File("vault.dat");

    private final List<VaultEntry> entries = new ArrayList<>();
    private boolean unlocked = false;

    /** A single stored credential. */
    public static class VaultEntry {
        public final String site;
        public final String username;
        public final String password;

        public VaultEntry(String site, String username, String password) {
            this.site = site;
            this.username = username;
            this.password = password;
        }
    }

    /** True if a vault file already exists on disk. */
    public boolean vaultExists() {
        return VAULT_FILE.exists();
    }

    /**
     * Unlocks (or creates) the vault with the given master password.
     * @return true if unlock succeeded, false if the password was wrong or the vault is corrupted.
     */
    public boolean unlock(char[] masterPassword) {
        entries.clear();
        if (!vaultExists()) {
            // First run: nothing to decrypt yet. An empty vault will be created on first save.
            unlocked = true;
            return true;
        }
        try {
            byte[] encrypted = readFile(VAULT_FILE);
            if (encrypted.length == 0) {
                // Empty vault file, nothing to decrypt.
                unlocked = true;
                return true;
            }
            byte[] decrypted = CryptoUtil.decrypt(encrypted, masterPassword);
            String text = new String(decrypted, StandardCharsets.UTF_8);
            parse(text);
            unlocked = true;
            return true;
        } catch (AEADBadTagException e) {
            // Authentication tag mismatch = wrong password OR tampered file.
            unlocked = false;
            return false;
        } catch (Exception e) {
            unlocked = false;
            return false;
        }
    }

    private void parse(String text) {
        if (text.isEmpty()) {
            return;
        }
        String[] lines = text.split("\n", -1);
        for (String line : lines) {
            if (line.isEmpty()) continue;
            String[] parts = line.split(FIELD_SEP, -1);
            if (parts.length == 3) {
                entries.add(new VaultEntry(parts[0], parts[1], parts[2]));
            }
        }
    }

    public void addEntry(String site, String username, String password) {
        requireUnlocked();
        entries.add(new VaultEntry(site, username, password));
    }

    public boolean deleteEntry(int index) {
        requireUnlocked();
        if (index < 0 || index >= entries.size()) {
            return false;
        }
        entries.remove(index);
        return true;
    }

    public List<VaultEntry> listEntries() {
        requireUnlocked();
        return new ArrayList<>(entries);
    }

    /** Encrypts the current in-memory entries and writes them to the vault file. */
    public void save(char[] masterPassword) throws Exception {
        requireUnlocked();
        StringBuilder sb = new StringBuilder();
        for (VaultEntry entry : entries) {
            sb.append(entry.site).append(FIELD_SEP)
              .append(entry.username).append(FIELD_SEP)
              .append(entry.password).append("\n");
        }
        byte[] plaintext = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = CryptoUtil.encrypt(plaintext, masterPassword);
        writeFile(VAULT_FILE, encrypted);
    }

    private void requireUnlocked() {
        if (!unlocked) {
            throw new IllegalStateException("Vault is locked. Call unlock() first.");
        }
    }

    private static byte[] readFile(File file) throws IOException {
        return java.nio.file.Files.readAllBytes(file.toPath());
    }

    private static void writeFile(File file, byte[] data) throws IOException {
        java.nio.file.Files.write(file.toPath(), data);
    }
}