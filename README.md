# 24BCY10141-JAVA-PROJECT
# CyberVault — A Java Cybersecurity Toolkit

CyberVault is a console-based Java application that brings together five
practical, industry-relevant cybersecurity tools into one program:

1. **File Encryption / Decryption** — AES-256-GCM authenticated encryption
2. **File Integrity Verification** — SHA-256 checksum generation & verification
3. **Password Strength Analyzer** — entropy + composition based scoring
4. **Secure Password Generator** — cryptographically random, policy-compliant
5. **Encrypted Password Vault** — a local, master-password-protected credential store

All cryptography is built on Java's own `javax.crypto` / `java.security`
APIs (no external/third-party libraries), using OWASP-recommended
primitives: **AES-256-GCM** for confidentiality + integrity, and
**PBKDF2WithHmacSHA256** (65,536 iterations) for password-based key
derivation.

---

## Project Structure

```
CyberVault/
└── src/
    ├── Main.java               # Console UI / menu, wires everything together
    ├── CryptoUtil.java         # AES-256-GCM encryption engine + PBKDF2 key derivation
    ├── FileIntegrityUtil.java  # SHA-256 checksum generation & verification
    ├── PasswordUtil.java       # Password strength scoring + secure random generator
    └── VaultManager.java       # Encrypted credential vault (add/view/delete/save)
```

## How to Compile & Run

```bash
cd CyberVault/src
javac *.java
java Main
```

No external dependencies or Maven/Gradle setup is required — it runs on
plain JDK 8+.

## Feature Walkthrough

### 1. File Encryption / Decryption
Encrypts any file (documents, images, archives) using **AES-256 in GCM
mode**. A random 16-byte salt and 12-byte IV are generated per file, the
AES key is derived from the user's password via PBKDF2, and the output
file is `[salt][iv][ciphertext+authTag]`. Because GCM is an *authenticated*
cipher mode, decryption will fail loudly (`AEADBadTagException`) if the
wrong password is used or if even a single byte of the file has been
tampered with — plaintext is never released on a failed check.

### 2. File Integrity Verification
Computes a SHA-256 digest of any file and can write it to a `.sha256`
sidecar file, or verify a file against a previously recorded hash — the
same technique used to confirm downloaded software or forensic evidence
hasn't been altered.

### 3. Password Strength Analyzer
Scores a password 0–100 using length, character-class variety (lower/
upper/digit/symbol), an estimated bits-of-entropy calculation, a check
against a common-breached-password list, and a check for repeating
character patterns. Returns a rating (Very Weak → Very Strong) with
concrete, actionable feedback.

### 4. Secure Password Generator
Generates passwords using `java.security.SecureRandom` (a CSPRNG, unlike
`java.util.Random`), guaranteeing at least one character from each of four
classes, then Fisher–Yates shuffling the result so the guaranteed
characters aren't predictably placed.

### 5. Encrypted Password Vault
A tiny local password manager. All entries (site, username, password) are
serialized to a single in-memory blob and encrypted as a whole with the
master password before ever touching disk (`vault.dat`). Nothing is ever
written in plaintext. Unlocking with the wrong master password is
detected via GCM's authentication tag rather than by any custom check.

## Security Design Notes

- **Why AES-GCM over AES-CBC?** GCM provides authenticated encryption
  (confidentiality *and* integrity/tamper-detection) in a single pass;
  CBC alone has no integrity check and is vulnerable to padding-oracle
  attacks.
- **Why PBKDF2 with 65,536 iterations?** Slows down brute-force/dictionary
  attacks against the derived key by making each guess computationally
  expensive, per OWASP password-storage guidance.
- **Why a random salt and IV per operation?** Prevents two identical
  plaintexts (or the same password reused) from ever producing the same
  ciphertext, and defeats precomputed rainbow-table attacks.
- Passwords are handled as `char[]` (not `String`) where possible and
  zeroed out after use, since `String` objects are immutable and can
  linger in memory/heap dumps.

## Sample Session

```
1. Encrypt a File (AES-256-GCM)
2. Decrypt a File
3. Generate SHA-256 Checksum for a File
4. Verify File Integrity Against a Checksum
5. Check Password Strength
6. Generate a Secure Random Password
7. Encrypted Password Vault
0. Exit
Choose an option: 5
Enter a password to analyze: Sunshine123
Score:    46/100
Rating:   Moderate
Feedback: Mix uppercase, lowercase, digits, and symbols.
```

## Possible Future Enhancements

- GUI front-end (JavaFX)
- Directory-level (recursive) encryption
- Configurable PBKDF2 iteration count / migration to Argon2id
- Vault export/import and multi-device sync
