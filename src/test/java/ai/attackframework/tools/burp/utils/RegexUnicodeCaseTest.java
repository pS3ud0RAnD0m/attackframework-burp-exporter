package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies Unicode-aware case-insensitive behavior (e.g., å ↔ Å).
 */
class RegexUnicodeCaseTest {

    @Test
    void caseInsensitive_unicodeCaseFolding_matches_upper_to_lower() {
        Pattern p = Regex.compile("å", /*caseSensitive*/ false, /*multiline*/ false);
        assertThat(p.matcher("Å").find()).isTrue();
        assertThat(p.matcher("fooÅbar").find()).isTrue();
    }

    @Test
    void caseSensitive_unicodeCaseFolding_doesNotMatch_upper_to_lower() {
        Pattern p = Regex.compile("å", /*caseSensitive*/ true, /*multiline*/ false);
        assertThat(p.matcher("Å").find()).isFalse();
        assertThat(p.matcher("fooÅbar").find()).isFalse();
    }

    @Test
    void caseInsensitive_unicodeCaseFolding_matches_lower_to_upper() {
        Pattern p = Regex.compile("Å", /*caseSensitive*/ false, /*multiline*/ false);
        assertThat(p.matcher("å").find()).isTrue();
        assertThat(p.matcher("fooåbar").find()).isTrue();
    }
}
