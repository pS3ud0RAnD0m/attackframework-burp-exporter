package ai.attackframework.tools.burp.utils.text;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for substring behavior in {@link TextSearchEngine}.
 *
 * <p>Covers:</p>
 * <ul>
 *   <li>Case-sensitive vs. case-insensitive substring matching.</li>
 *   <li>Non-overlapping match semantics (typical "find next" behavior).</li>
 *   <li>No match when the needle is longer than the haystack.</li>
 * </ul>
 */
class TextSearchEngineSubstringTest {

    /**
     * Verifies case-sensitive vs case-insensitive substring behavior.
     */
    @Test
    void substring_caseSensitivity() {
        String hay = "Foo foo FOO";

        // case-insensitive: all three "foo" variants match
        TextQuery ci = new TextQuery("foo", /*caseSensitive*/ false, /*regex*/ false, /*multiline*/ false);
        List<int[]> ciRanges = TextSearchEngine.findAll(hay, ci);
        assertThat(ciRanges).hasSize(3);
        assertThat(snippets(hay, ciRanges)).containsExactly("Foo", "foo", "FOO");

        // case-sensitive: only the exact lower-case "foo" matches
        TextQuery cs = new TextQuery("foo", /*caseSensitive*/ true, /*regex*/ false, /*multiline*/ false);
        List<int[]> csRanges = TextSearchEngine.findAll(hay, cs);
        assertThat(csRanges).hasSize(1);
        assertThat(snippets(hay, csRanges)).containsExactly("foo");
    }

    /**
     * Verifies substring matches are non-overlapping.
     */
    @Test
    void substring_nonOverlapping() {
        String hay = "aaaaa";     // indexes: 0 1 2 3 4
        String needle = "aa";     // matches at [0,2] and [2,4] for non-overlapping semantics

        TextQuery q = new TextQuery(needle, /*caseSensitive*/ true, /*regex*/ false, /*multiline*/ false);
        List<int[]> ranges = TextSearchEngine.findAll(hay, q);
        assertThat(ranges).hasSize(2);
        assertThat(snippets(hay, ranges)).containsExactly("aa", "aa");
        // Ensure non-overlap by checking the start of the second range equals the end of the first.
        assertThat(ranges.get(1)[0]).isEqualTo(ranges.get(0)[1]);
    }

    /**
     * Needle longer than haystack yields no matches.
     */
    @Test
    void substring_needle_longer_than_haystack() {
        String hay = "abc";
        String needle = "abcd";
        TextQuery q = new TextQuery(needle, /*caseSensitive*/ true, /*regex*/ false, /*multiline*/ false);
        assertThat(TextSearchEngine.findAll(hay, q)).isEmpty();
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
