import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
 * PasswordUtil
 * ------------
 * Evaluates password strength using entropy + composition heuristics, and
 * generates cryptographically strong random passwords using SecureRandom
 * (never java.util.Random, which is predictable and unsafe for security use).
 */
public class PasswordUtil {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";

    private static final Set<String> COMMON_PASSWORDS = new HashSet<>();
    static {
        String[] common = {
            "password", "123456", "123456789", "qwerty", "abc123", "password1",
            "111111", "12345678", "letmein", "iloveyou", "admin", "welcome",
            "monkey", "dragon", "football", "1234567890"
        };
        for (String p : common) {
            COMMON_PASSWORDS.add(p);
        }
    }

    private PasswordUtil() {
    }

    /** Result of a password strength evaluation. */
    public static class StrengthResult {
        public final int score;          // 0-100
        public final String rating;      // Very Weak / Weak / Moderate / Strong / Very Strong
        public final String feedback;    // human-readable suggestions

        public StrengthResult(int score, String rating, String feedback) {
            this.score = score;
            this.rating = rating;
            this.feedback = feedback;
        }
    }

    /** Analyzes password strength based on length, character diversity, and known-weak lists. */
    public static StrengthResult evaluate(String password) {
        if (password == null || password.isEmpty()) {
            return new StrengthResult(0, "Very Weak", "Password cannot be empty.");
        }

        StringBuilder feedback = new StringBuilder();
        int score = 0;

        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSymbol = password.chars().anyMatch(c -> SYMBOLS.indexOf(c) >= 0);

        int variety = 0;
        if (hasLower) variety++;
        if (hasUpper) variety++;
        if (hasDigit) variety++;
        if (hasSymbol) variety++;

        // Length scoring (up to 40 points)
        int length = password.length();
        if (length >= 16) score += 40;
        else if (length >= 12) score += 30;
        else if (length >= 8) score += 18;
        else if (length >= 5) score += 8;
        else score += 2;

        // Character variety scoring (up to 40 points)
        score += variety * 10;

        // Estimated entropy bonus (up to 20 points)
        double poolSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSymbol ? SYMBOLS.length() : 0);
        double entropyBits = poolSize > 0 ? length * (Math.log(poolSize) / Math.log(2)) : 0;
        if (entropyBits >= 80) score += 20;
        else if (entropyBits >= 60) score += 14;
        else if (entropyBits >= 40) score += 8;
        else if (entropyBits >= 20) score += 3;

        // Penalties
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            score = Math.min(score, 5);
            feedback.append("This is one of the most commonly breached passwords in the world. ");
        }
        if (hasRepeatingPattern(password)) {
            score -= 10;
            feedback.append("Avoid repeating characters or sequences (e.g. 'aaa', '123123'). ");
        }
        if (length < 8) {
            feedback.append("Use at least 8 characters, ideally 12+. ");
        }
        if (variety < 3) {
            feedback.append("Mix uppercase, lowercase, digits, and symbols. ");
        }

        score = Math.max(0, Math.min(100, score));

        String rating;
        if (score < 20) rating = "Very Weak";
        else if (score < 40) rating = "Weak";
        else if (score < 60) rating = "Moderate";
        else if (score < 80) rating = "Strong";
        else rating = "Very Strong";

        if (feedback.length() == 0) {
            feedback.append("Good password hygiene. Keep it unique to this account.");
        }

        return new StrengthResult(score, rating, feedback.toString().trim());
    }

    private static boolean hasRepeatingPattern(String password) {
        for (int i = 0; i + 2 < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i + 1) && password.charAt(i + 1) == password.charAt(i + 2)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generates a cryptographically secure random password containing at least
     * one lowercase letter, one uppercase letter, one digit, and one symbol.
     */
    public static String generateSecurePassword(int length) {
        if (length < 8) {
            length = 8; // enforce a sane minimum
        }
        SecureRandom random = new SecureRandom();
        String allChars = LOWER + UPPER + DIGITS + SYMBOLS;

        char[] result = new char[length];
        // Guarantee at least one character from each required category
        result[0] = LOWER.charAt(random.nextInt(LOWER.length()));
        result[1] = UPPER.charAt(random.nextInt(UPPER.length()));
        result[2] = DIGITS.charAt(random.nextInt(DIGITS.length()));
        result[3] = SYMBOLS.charAt(random.nextInt(SYMBOLS.length()));

        for (int i = 4; i < length; i++) {
            result[i] = allChars.charAt(random.nextInt(allChars.length()));
        }

        // Shuffle (Fisher-Yates) so the guaranteed characters aren't always at the front
        for (int i = result.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = result[i];
            result[i] = result[j];
            result[j] = temp;
        }

        return new String(result);
    }
}