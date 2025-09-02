package ai.attackframework.tools.burp.utils.text;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for regex behavior in {@link TextSearchEngine}.
 *
 * <p>Covers:</p>
 * <ul>
 *   <li>Case-sensitive vs. case-insensitive matching.</li>
 *   <li>Multiline anchors {@code ^} and {@code $} across line boundaries.</li>
 *   <li>Blank/null query short-circuit.</li>
 *   <li>Invalid patterns surface as {@link java.util.regex.PatternSyntaxException}.</li>
 * </ul>
 */
class TextSearchEngineRegexTest {

    @Test
    void regex_caseSensitivity() {
        String hay = "Foo foo FOO";

        // case-insensitive: all three "foo" variants match
        TextQuery ci = new TextQuery("foo", /*caseSensitive*/ false, /*regex*/ true, /*multiline*/ false);
        List<int[]> ciRanges = TextSearchEngine.findAll(hay, ci);
        assertThat(ciRanges).hasSize(3);
        assertThat(snippets(hay, ciRanges)).containsExactly("Foo", "foo", "FOO");

        // case-sensitive: only the exact lower-case "foo" matches
        TextQuery cs = new TextQuery("foo", /*caseSensitive*/ true, /*regex*/ true, /*multiline*/ false);
        List<int[]> csRanges = TextSearchEngine.findAll(hay, cs);
        assertThat(csRanges).hasSize(1);
        assertThat(snippets(hay, csRanges)).containsExactly("foo");
    }

    @Test
    void regex_multilineAnchors() {
        String hay = "alpha\nbeta\ngamma";

        // ^beta$ should match exactly the middle line when multiline is on
        TextQuery q1 = new TextQuery("^beta$", /*caseSensitive*/ true, /*regex*/ true, /*multiline*/ true);
        List<int[]> r1 = TextSearchEngine.findAll(hay, q1);
        assertThat(snippets(hay, r1)).containsExactly("beta");

        // Lines that start with 'a' or 'g' and end with 'a' -> alpha, gamma
        TextQuery q2 = new TextQuery("^[ag].*a$", /*caseSensitive*/ true, /*regex*/ true, /*multiline*/ true);
        List<int[]> r2 = TextSearchEngine.findAll(hay, q2);
        assertThat(snippets(hay, r2)).containsExactly("alpha", "gamma");
    }

    @Test
    void blank_or_null_query_returns_empty() {
        String hay = "anything";

        List<int[]> blank = TextSearchEngine.findAll(hay, new TextQuery("", true, true, false));
        assertThat(blank).isEmpty();

        List<int[]> nullQ = TextSearchEngine.findAll(hay, new TextQuery(null, true, true, false));
        assertThat(nullQ).isEmpty();
    }

    @Test
    void invalid_pattern_throws() {
        String hay = "text";
        TextQuery bad = new TextQuery("[unterminated", true, true, false);
        assertThatThrownBy(() -> TextSearchEngine.findAll(hay, bad))
                .isInstanceOf(java.util.regex.PatternSyntaxException.class);
    }

    /* ----------------------------- helpers ----------------------------- */

    private static List<String> snippets(String hay, List<int[]> ranges) {
        List<String> out = new ArrayList<>(ranges.size());
        for (int[] r : ranges) {
            out.add(hay.substring(r[0], r[1]));
        }
        return out;
    }
}
