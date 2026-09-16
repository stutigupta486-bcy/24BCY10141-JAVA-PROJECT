import java.io.Console;
import java.io.File;
import java.util.List;
import java.util.Scanner;

/**
 * Main
 * ----
 * CyberVault - A Java Cybersecurity Toolkit
 * Console entry point that ties together file encryption, integrity
 * verification, password strength analysis, secure password generation,
 * and an encrypted credential vault.
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        printBanner();
        boolean running = true;
        while (running) {
            printMenu();
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1":
                    handleEncryptFile();
                    break;
                case "2":
                    handleDecryptFile();
                    break;
                case "3":
                    handleGenerateChecksum();
                    break;
                case "4":
                    handleVerifyChecksum();
                    break;
                case "5":
                    handlePasswordStrength();
                    break;
                case "6":
                    handleGeneratePassword();
                    break;
                case "7":
                    handleVaultMenu();
                    break;
                case "0":
                    running = false;
                    System.out.println("\nGoodbye. Stay secure.");
                    break;
                default:
                    System.out.println("Invalid choice. Please select a valid option.\n");
            }
        }
        scanner.close();
    }

    private static void printBanner() {
        System.out.println("=============================================");
        System.out.println("   CyberVault - Java Cybersecurity Toolkit");
        System.out.println("=============================================");
    }

    private static void printMenu() {
        System.out.println("\n----------------- MAIN MENU -----------------");
        System.out.println("1. Encrypt a File (AES-256-GCM)");
        System.out.println("2. Decrypt a File");
        System.out.println("3. Generate SHA-256 Checksum for a File");
        System.out.println("4. Verify File Integrity Against a Checksum");
        System.out.println("5. Check Password Strength");
        System.out.println("6. Generate a Secure Random Password");
        System.out.println("7. Encrypted Password Vault");
        System.out.println("0. Exit");
        System.out.print("Choose an option: ");
    }

    // ---------- File Encryption ----------

    private static void handleEncryptFile() {
        try {
            System.out.print("Enter path of file to encrypt: ");
            File input = new File(scanner.nextLine().trim());
            if (!input.exists() || !input.isFile()) {
                System.out.println("File not found: " + input.getPath());
                return;
            }
            System.out.print("Enter output path for encrypted file (e.g. secret.enc): ");
            File output = new File(scanner.nextLine().trim());
            char[] password = readPassword("Enter encryption password: ");

            CryptoUtil.encryptFile(input, output, password);
            java.util.Arrays.fill(password, '\0');

            System.out.println("File encrypted successfully -> " + output.getPath());
        } catch (Exception e) {
            System.out.println("Encryption failed: " + e.getMessage());
        }
    }

    private static void handleDecryptFile() {
        try {
            System.out.print("Enter path of encrypted file: ");
            File input = new File(scanner.nextLine().trim());
            if (!input.exists() || !input.isFile()) {
                System.out.println("File not found: " + input.getPath());
                return;
            }
            System.out.print("Enter output path for decrypted file: ");
            File output = new File(scanner.nextLine().trim());
            char[] password = readPassword("Enter decryption password: ");

            CryptoUtil.decryptFile(input, output, password);
            java.util.Arrays.fill(password, '\0');

            System.out.println("File decrypted successfully -> " + output.getPath());
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Decryption failed: wrong password or the file has been tampered with.");
        } catch (Exception e) {
            System.out.println("Decryption failed: " + e.getMessage());
        }
    }

    // ---------- Integrity Checking ----------

    private static void handleGenerateChecksum() {
        try {
            System.out.print("Enter path of file to hash: ");
            File file = new File(scanner.nextLine().trim());
            if (!file.exists() || !file.isFile()) {
                System.out.println("File not found: " + file.getPath());
                return;
            }
            String hash = FileIntegrityUtil.computeSHA256(file);
            File checksumFile = FileIntegrityUtil.generateChecksumFile(file);
            System.out.println("SHA-256: " + hash);
            System.out.println("Checksum saved to: " + checksumFile.getPath());
        } catch (Exception e) {
            System.out.println("Checksum generation failed: " + e.getMessage());
        }
    }

    private static void handleVerifyChecksum() {
        try {
            System.out.print("Enter path of file to verify: ");
            File file = new File(scanner.nextLine().trim());
            if (!file.exists() || !file.isFile()) {
                System.out.println("File not found: " + file.getPath());
                return;
            }
            System.out.print("Enter expected SHA-256 hash: ");
            String expected = scanner.nextLine().trim();
            boolean match = FileIntegrityUtil.verify(file, expected);
            if (match) {
                System.out.println("MATCH - file integrity verified. No tampering detected.");
            } else {
                System.out.println("MISMATCH - file has been modified or the hash is incorrect!");
            }
        } catch (Exception e) {
            System.out.println("Verification failed: " + e.getMessage());
        }
    }

    // ---------- Password Tools ----------

    private static void handlePasswordStrength() {
        System.out.print("Enter a password to analyze: ");
        String password = scanner.nextLine();
        PasswordUtil.StrengthResult result = PasswordUtil.evaluate(password);
        System.out.println("Score:    " + result.score + "/100");
        System.out.println("Rating:   " + result.rating);
        System.out.println("Feedback: " + result.feedback);
    }

    private static void handleGeneratePassword() {
        System.out.print("Enter desired password length (min 8, default 16): ");
        String lengthInput = scanner.nextLine().trim();
        int length;
        try {
            length = lengthInput.isEmpty() ? 16 : Integer.parseInt(lengthInput);
        } catch (NumberFormatException e) {
            System.out.println("Invalid number, defaulting to 16.");
            length = 16;
        }
        String generated = PasswordUtil.generateSecurePassword(length);
        System.out.println("Generated password: " + generated);
        PasswordUtil.StrengthResult result = PasswordUtil.evaluate(generated);
        System.out.println("Strength: " + result.rating + " (" + result.score + "/100)");
    }

    // ---------- Encrypted Vault ----------

    private static void handleVaultMenu() {
        VaultManager vault = new VaultManager();
        boolean firstTime = !vault.vaultExists();
        char[] masterPassword = readPassword(firstTime
                ? "No vault found. Create a master password: "
                : "Enter master password to unlock vault: ");

        if (!vault.unlock(masterPassword)) {
            System.out.println("Incorrect master password or corrupted vault file.");
            return;
        }
        System.out.println(firstTime ? "New vault created." : "Vault unlocked.");

        boolean inVault = true;
        while (inVault) {
            System.out.println("\n------------- VAULT MENU -------------");
            System.out.println("1. View saved credentials");
            System.out.println("2. Add a new credential");
            System.out.println("3. Delete a credential");
            System.out.println("4. Save and lock vault");
            System.out.print("Choose an option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    List<VaultManager.VaultEntry> entries = vault.listEntries();
                    if (entries.isEmpty()) {
                        System.out.println("Vault is empty.");
                    } else {
                        for (int i = 0; i < entries.size(); i++) {
                            VaultManager.VaultEntry e = entries.get(i);
                            System.out.printf("[%d] Site: %s | Username: %s | Password: %s%n",
                                    i, e.site, e.username, e.password);
                        }
                    }
                    break;
                case "2":
                    System.out.print("Site/App name: ");
                    String site = scanner.nextLine().trim();
                    System.out.print("Username: ");
                    String username = scanner.nextLine().trim();
                    System.out.print("Password (leave blank to auto-generate): ");
                    String pwd = scanner.nextLine();
                    if (pwd.isEmpty()) {
                        pwd = PasswordUtil.generateSecurePassword(16);
                        System.out.println("Generated: " + pwd);
                    }
                    vault.addEntry(site, username, pwd);
                    System.out.println("Credential added (not yet saved to disk).");
                    break;
                case "3":
                    System.out.print("Enter index of credential to delete: ");
                    try {
                        int idx = Integer.parseInt(scanner.nextLine().trim());
                        if (vault.deleteEntry(idx)) {
                            System.out.println("Deleted entry " + idx + ".");
                        } else {
                            System.out.println("Invalid index.");
                        }
                    } catch (NumberFormatException e) {
                        System.out.println("Please enter a valid number.");
                    }
                    break;
                case "4":
                    try {
                        vault.save(masterPassword);
                        System.out.println("Vault saved and encrypted successfully.");
                    } catch (Exception e) {
                        System.out.println("Failed to save vault: " + e.getMessage());
                    }
                    inVault = false;
                    break;
                default:
                    System.out.println("Invalid choice.");
            }
        }
        java.util.Arrays.fill(masterPassword, '\0');
    }

    // ---------- Helper ----------

    /** Reads a password without echoing it to the screen when a real console is available. */
    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        // Fallback for IDEs / environments without a real console (input will be visible).
        System.out.print(prompt);
        return scanner.nextLine().toCharArray();
    }
}