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
     * @param caseSensitive whether the match is case-sensitive
     * @param multiline     whether {@link Pattern#MULTILINE} should be applied
     * @return combined flags for {@link Pattern#compile(String, int)}
     */
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
}
