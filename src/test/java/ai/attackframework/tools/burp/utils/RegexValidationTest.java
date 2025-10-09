package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link Regex#isValid(String, boolean, boolean)} and {@link Regex#compileOrNull(String, boolean, boolean)}.
 */
class RegexValidationTest {

    @Test
    void isValid_true_for_valid_patterns() {
        assertThat(Regex.isValid("foo.*bar", true, false)).isTrue();
        assertThat(Regex.isValid("^abc$", true, true)).isTrue();
        assertThat(Regex.isValid("", true, false)).isTrue(); // empty pattern is valid
    }

    @Test
    void isValid_false_for_invalid_or_null() {
        assertThat(Regex.isValid(null, true, false)).isFalse();
        assertThat(Regex.isValid("[unterminated", true, false)).isFalse();
    }

    @Test
    void compileOrNull_returns_pattern_or_null() {
        Pattern p1 = Regex.compileOrNull("foo", true, false);
        assertThat(p1).isNotNull();
        assertThat(p1.matcher("food").find()).isTrue();

        Pattern p2 = Regex.compileOrNull("[unterminated", true, false);
        assertThat(p2).isNull();
    }
}
