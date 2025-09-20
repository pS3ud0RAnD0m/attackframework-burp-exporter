package ai.attackframework.tools.burp.utils.config;

import java.util.List;

/**
 * Typed configuration model for import/export and UI binding.
 * Immutable records with defensive copying where lists are provided.
 */
public final class ConfigState {

    /** Scope kind for {@link ScopeEntry}. */
    public enum Kind { REGEX, STRING }

    /** Ordered custom-scope entry. */
    public record ScopeEntry(String value, Kind kind) {
        public ScopeEntry {
            value = value == null ? "" : value;
            kind  = kind == null ? Kind.REGEX : kind;
        }
    }

    /** Sinks selection and values. */
    public record Sinks(boolean filesEnabled, String filesPath,
                        boolean osEnabled, String openSearchUrl) { }

    /** Top-level state. */
    public record State(List<String> dataSources,
                        String scopeType,               // "all" | "burp" | "custom"
                        List<ScopeEntry> customEntries, // ordered; used when scopeType=custom
                        Sinks sinks) {

        public State {
            dataSources   = dataSources == null ? List.of() : List.copyOf(dataSources);
            scopeType     = scopeType   == null ? "all"     : scopeType;
            customEntries = customEntries == null ? List.of() : List.copyOf(customEntries);
        }
    }

    private ConfigState() { }
}
