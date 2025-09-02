package ai.attackframework.tools.burp.utils.text;

/**
 * Immutable description of a user text query used by validation and search code.
 *
 * <p>This record intentionally contains only the minimum state required to derive regex flags
 * and substring behavior. It has no Swing dependencies and can be used by any module.</p>
 */
public record TextQuery(String query, boolean caseSensitive, boolean regex, boolean multiline) {

    /**
     * Indicates whether the query string is null/blank and therefore not actionable.
     * Callers should short-circuit search/validation when this returns {@code true}.
     *
     * @return {@code true} if the query is {@code null} or blank
     */
    public boolean isBlank() {
        return query == null || query.isBlank();
    }
}
