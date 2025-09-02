package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for flag/compile helpers in {@link Regex}.
 *
 * <p>Covers:</p>
 * <ul>
 *   <li>Flag derivation for case-insensitive vs. case-sensitive and multiline toggles.</li>
 *   <li>Successful compilation for valid patterns with derived flags.</li>
 *   <li>Pattern syntax errors surfaced on invalid patterns.</li>
 * </ul>
 */
class RegexFlagsCompileTest {

    /**
     * When case-insensitive and not multiline, flags must include
     * {@link Pattern#CASE_INSENSITIVE} and {@link Pattern#UNICODE_CASE}, and exclude {@link Pattern#MULTILINE}.
     */
    @Test
    void flags_caseInsensitive_unicode_noMultiline() {
        int flags = Regex.flags(/*caseSensitive*/ false, /*multiline*/ false);
        assertThat((flags & Pattern.CASE_INSENSITIVE)).as("CASE_INSENSITIVE set").isNotZero();
        assertThat((flags & Pattern.UNICODE_CASE)).as("UNICODE_CASE set").isNotZero();
        assertThat((flags & Pattern.MULTILINE)).as("MULTILINE not set").isZero();
    }

    /**
     * When case-sensitive and multiline, flags must include only {@link Pattern#MULTILINE}.
     */
    @Test
    void flags_caseSensitive_multiline_only() {
        int flags = Regex.flags(/*caseSensitive*/ true, /*multiline*/ true);
        assertThat((flags & Pattern.CASE_INSENSITIVE)).as("CASE_INSENSITIVE not set").isZero();
        assertThat((flags & Pattern.UNICODE_CASE)).as("UNICODE_CASE not set").isZero();
        assertThat((flags & Pattern.MULTILINE)).as("MULTILINE set").isNotZero();
    }

    /**
     * Valid patterns compile with derived flags.
     */
    @Test
    void compile_valid_patterns() {
        Pattern p1 = Regex.compile("foo", /*caseSensitive*/ false, /*multiline*/ false);
        assertThat(p1.matcher("FOO").find()).as("CI match works").isTrue();

        Pattern p2 = Regex.compile("^abc$", /*caseSensitive*/ true, /*multiline*/ true);
        assertThat(p2.matcher("xyz\nabc\nzzz").find()).as("multiline anchors work").isTrue();
    }

    /**
     * Invalid patterns throw {@link java.util.regex.PatternSyntaxException}.
     */
    @Test
    void compile_invalid_pattern_throws() {
        assertThatThrownBy(() -> Regex.compile("[unterminated", /*caseSensitive*/ true, /*multiline*/ false))
                .isInstanceOf(java.util.regex.PatternSyntaxException.class);
    }
}
