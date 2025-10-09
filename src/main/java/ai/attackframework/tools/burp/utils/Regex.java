package ai.attackframework.tools.burp.utils;

import java.util.regex.Pattern;

/**
 * Centralized helpers for regex compilation and flag derivation.
 *
 * <p>Keeping flag logic in one place avoids drift between UI components and utilities.</p>
 */
public final class Regex {

    private Regex() {
        // utility class
    }

    /**
     * Derive {@link Pattern} flags from UI toggles.
     *
     * @param caseSensitive whether matching is case-sensitive
     * @param multiline     whether {@link Pattern#MULTILINE} should be applied
     * @return integer bitmask for {@link Pattern#compile(String, int)}
     */
    // returns only combinations of Pattern flags
    public static int flags(boolean caseSensitive, boolean multiline) {
        int flags = 0;
        if (!caseSensitive) {
            flags |= Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
        }
        if (multiline) {
            flags |= Pattern.MULTILINE;
        }
        return flags;
    }

    /**
     * Compile a pattern with flags derived from the provided toggles.
     *
     * @param pattern       the regex pattern text
     * @param caseSensitive whether the match is case-sensitive
     * @param multiline     whether {@link Pattern#MULTILINE} should be applied
     * @return compiled {@link Pattern}
     * @throws java.util.regex.PatternSyntaxException if the pattern is invalid
     */
    @SuppressWarnings("MagicConstant") // flags(caseSensitive, multiline) intentionally combines valid Pattern flags
    public static Pattern compile(String pattern, boolean caseSensitive, boolean multiline) {
        return Pattern.compile(pattern, flags(caseSensitive, multiline));
    }

    /**
     * Returns whether the supplied pattern compiles with the derived flags.
     *
     * <p>This is a convenience for UI validation paths that should not rely on
     * exception-driven control flow while the user is typing.</p>
     *
     * @param pattern       the pattern text (may be {@code null})
     * @param caseSensitive whether the match is case-sensitive
     * @param multiline     whether {@link Pattern#MULTILINE} should be applied
     * @return {@code true} if {@link #compile(String, boolean, boolean)} succeeds; {@code false} otherwise
     */
    public static boolean isValid(String pattern, boolean caseSensitive, boolean multiline) {
        if (pattern == null) {
            return false;
        }
        try {
            compile(pattern, caseSensitive, multiline);
            return true;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /**
     * Compile a pattern or return {@code null} if invalid.
     *
     * @param pattern       the pattern text (may be {@code null})
     * @param caseSensitive whether the match is case-sensitive
     * @param multiline     whether {@link Pattern#MULTILINE} should be applied
     * @return compiled {@link Pattern} or {@code null} if invalid
     */
    public static Pattern compileOrNull(String pattern, boolean caseSensitive, boolean multiline) {
        if (pattern == null) {
            return null;
        }
        try {
            return compile(pattern, caseSensitive, multiline);
        } catch (RuntimeException ex) {
            return null;
        }
    }
}
