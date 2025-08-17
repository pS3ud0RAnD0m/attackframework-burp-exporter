package ai.attackframework.tools.burp.utils;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Minimal, UI-agnostic regex validation helper. */
public final class Regex {
    private Regex() { }

    /** Result of validating a pattern. {@code error} is null when {@code valid} is true. */
    public record Validation(boolean valid, String error) { }

    /** Validate a pattern with Pattern flags. Empty/null patterns are treated as valid. */
    @SuppressWarnings("MagicConstant")
    public static Validation validate(String pattern, int flags) {
        if (pattern == null || pattern.isBlank()) {
            return new Validation(true, null);
        }
        try {
            Pattern.compile(pattern, flags);
            return new Validation(true, null);
        } catch (PatternSyntaxException ex) {
            return new Validation(false, ex.getMessage());
        }
    }

    /** Convenience: true if the pattern compiles (or is empty/null). */
    @SuppressWarnings("unused")
    public static boolean isValid(String pattern, int flags) {
        return validate(pattern, flags).valid();
    }
}
