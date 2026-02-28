package ai.attackframework.tools.burp.utils.config;

import java.util.List;

/**
 * Typed configuration model for import/export and UI binding.
 * Immutable records with defensive copying where lists are provided.
 */
public final class ConfigState {

    /** Default settings sub-options (project, user). */
    public static final List<String> DEFAULT_SETTINGS_SUB =
            List.of(ConfigKeys.SRC_SETTINGS_PROJECT, ConfigKeys.SRC_SETTINGS_USER);

    /** Default traffic tool types: empty (no traffic exported by default). */
    public static final List<String> DEFAULT_TRAFFIC_TOOL_TYPES = List.of();

    /** Legacy default for traffic when parsing config without dataSourceOptions (PROXY, REPEATER). */
    public static final List<String> LEGACY_TRAFFIC_TOOL_TYPES = List.of("PROXY", "REPEATER");

    /** Default findings severities: all five. */
    public static final List<String> DEFAULT_FINDINGS_SEVERITIES =
            List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");

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
                        Sinks sinks,
                        List<String> settingsSub,       // "project", "user"; default both
                        List<String> trafficToolTypes,  // ToolType names; default empty (no traffic)
                        List<String> findingsSeverities) { // AuditIssueSeverity names; default all five

        public State {
            dataSources       = dataSources == null ? List.of() : List.copyOf(dataSources);
            scopeType         = scopeType == null ? "all" : scopeType;
            customEntries     = customEntries == null ? List.of() : List.copyOf(customEntries);
            settingsSub       = settingsSub == null ? List.of() : List.copyOf(settingsSub);
            trafficToolTypes  = trafficToolTypes == null ? List.of() : List.copyOf(trafficToolTypes);
            findingsSeverities = findingsSeverities == null ? List.of() : List.copyOf(findingsSeverities);
        }
    }

    private ConfigState() { }
}
