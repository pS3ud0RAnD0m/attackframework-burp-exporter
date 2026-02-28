package ai.attackframework.tools.burp.utils.config;

import java.util.List;

/**
 * Holds the current runtime configuration for export pipelines.
 *
 * <p>UI actions update this state, and runtime exporters read from it. The export-running
 * flag gates whether traffic (and future sources) are actually sent to sinks; Start/Stop
 * in the UI toggle this without changing saved config.</p>
 */
public final class RuntimeConfig {
    private static volatile ConfigState.State state = defaultState();
    private static volatile boolean exportRunning = false;

    private RuntimeConfig() { }

    /** Returns the current runtime config state. */
    public static ConfigState.State getState() {
        return state;
    }

    /**
     * Returns whether export is currently running (Start pressed).
     *
     * <p>When {@code false}, traffic and other exporters do not send data to sinks.</p>
     *
     * @return {@code true} if export has been started and not stopped
     */
    public static boolean isExportRunning() {
        return exportRunning;
    }

    /**
     * Sets the export-running flag.
     *
     * <p>Start button sets {@code true}; Stop button sets {@code false}.</p>
     *
     * @param running new running state
     */
    public static void setExportRunning(boolean running) {
        exportRunning = running;
    }

    /** Updates the runtime config state with a normalized, non-null value. */
    public static void updateState(ConfigState.State newState) {
        state = normalize(newState);
    }

    /** True when OpenSearch export is enabled for the traffic source and at least one tool type is selected. */
    public static boolean isOpenSearchTrafficEnabled() {
        ConfigState.State current = state;
        return current != null
                && current.sinks().osEnabled()
                && current.dataSources().contains(ConfigKeys.SRC_TRAFFIC)
                && current.trafficToolTypes() != null
                && !current.trafficToolTypes().isEmpty();
    }

    /** Current OpenSearch URL for runtime exports. */
    public static String openSearchUrl() {
        ConfigState.State current = state;
        return current == null ? "" : safe(current.sinks().openSearchUrl());
    }

    private static ConfigState.State normalize(ConfigState.State incoming) {
        if (incoming == null) {
            return defaultState();
        }

        List<String> sources = incoming.dataSources() == null
                ? List.of()
                : List.copyOf(incoming.dataSources());
        List<ConfigState.ScopeEntry> custom = incoming.customEntries() == null
                ? List.of()
                : List.copyOf(incoming.customEntries());

        ConfigState.Sinks sinks = incoming.sinks();
        ConfigState.Sinks normalizedSinks = sinks == null
                ? new ConfigState.Sinks(false, "", false, "")
                : new ConfigState.Sinks(
                        sinks.filesEnabled(),
                        safe(sinks.filesPath()),
                        sinks.osEnabled(),
                        safe(sinks.openSearchUrl())
                );

        String scopeType = normalizeScopeType(incoming.scopeType());

        List<String> settingsSub = incoming.settingsSub() != null && !incoming.settingsSub().isEmpty()
                ? List.copyOf(incoming.settingsSub())
                : ConfigState.DEFAULT_SETTINGS_SUB;
        List<String> trafficToolTypes = incoming.trafficToolTypes() != null
                ? List.copyOf(incoming.trafficToolTypes())
                : ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES;
        List<String> findingsSeverities = incoming.findingsSeverities() != null && !incoming.findingsSeverities().isEmpty()
                ? List.copyOf(incoming.findingsSeverities())
                : ConfigState.DEFAULT_FINDINGS_SEVERITIES;

        return new ConfigState.State(sources, scopeType, custom, normalizedSinks,
                settingsSub, trafficToolTypes, findingsSeverities);
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    /**
     * Normalizes scope type to lowercase and trims; unknown values default to {@link ConfigKeys#SCOPE_ALL}.
     *
     * @param raw scope type from config; may be {@code null}
     * @return one of {@code "all"}, {@code "burp"}, {@code "custom"}
     */
    private static String normalizeScopeType(String raw) {
        if (raw == null || raw.isBlank()) {
            return ConfigKeys.SCOPE_ALL;
        }
        String normalized = raw.trim().toLowerCase(java.util.Locale.ROOT);
        if (ConfigKeys.SCOPE_BURP.equals(normalized) || ConfigKeys.SCOPE_CUSTOM.equals(normalized)) {
            return normalized;
        }
        return ConfigKeys.SCOPE_ALL;
    }

    private static ConfigState.State defaultState() {
        return new ConfigState.State(
                List.of(),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, ""),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES
        );
    }
}