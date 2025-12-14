package ai.attackframework.tools.burp.utils.text;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ai.attackframework.tools.burp.utils.Regex;

/**
 * Stateless search utility that returns all match ranges for either a regex query
 * or a plain substring query. No Swing dependencies.
 *
 * <h3>Design notes</h3>
 * <ul>
 *   <li>Regex compilation/flags are delegated to {@link Regex} to keep flag logic centralized.</li>
 *   <li>Substring matches are <strong>non-overlapping</strong> by design (typical “find next” behavior).</li>
 *   <li>Returned ranges are half-open pairs {@code [start, end]} in document indexing space.</li>
 * </ul>
 */
public final class TextSearchEngine {

    private TextSearchEngine() {}

    /**
     * Find all match ranges for the given query.
     *
     * @param haystack text to search; {@code null} is treated as empty
     * @param q        query descriptor (regex/substring, case, multiline)
     * @return list of half-open ranges {@code [start, end]} (never {@code null})
     * @throws NullPointerException if {@code q} is {@code null}
     */
    public static List<int[]> findAll(String haystack, TextQuery q) {
        Objects.requireNonNull(q, "TextQuery");
        final String text = haystack == null ? "" : haystack;
        if (q.isBlank()) return List.of();

        if (q.regex()) {
            final Pattern p = Regex.compile(q.query(), q.caseSensitive(), q.multiline());
            final Matcher m = p.matcher(text);
            final List<int[]> ranges = new ArrayList<>();
            while (m.find()) {
                ranges.add(new int[]{ m.start(), m.end() });
            }
            return ranges;
        } else {
            final boolean cs = q.caseSensitive();
            final String hay = cs ? text : text.toLowerCase(Locale.ROOT);
            final String needle = cs ? q.query() : q.query().toLowerCase(Locale.ROOT);
            final List<int[]> ranges = new ArrayList<>();
            int idx = 0;
            while (true) {
                idx = hay.indexOf(needle, idx);
                if (idx < 0) break;
                final int end = idx + needle.length();
                ranges.add(new int[]{ idx, end });
                idx = end; // non-overlapping behavior
            }
            return ranges;
        }
    }
}
