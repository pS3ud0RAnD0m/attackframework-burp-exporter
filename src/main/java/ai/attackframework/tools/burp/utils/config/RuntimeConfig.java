package ai.attackframework.tools.burp.utils.config;

import java.util.List;

/**
 * Holds the current runtime configuration for export pipelines.
 *
 * <p>UI actions update this state, and runtime exporters read from it.</p>
 */
public final class RuntimeConfig {
    private static volatile ConfigState.State state = defaultState();

    private RuntimeConfig() { }

    /** Returns the current runtime config state. */
    public static ConfigState.State getState() {
        return state;
    }

    /** Updates the runtime config state with a normalized, non-null value. */
    public static void updateState(ConfigState.State newState) {
        state = normalize(newState);
    }

    /** True when OpenSearch export is enabled for the traffic source. */
    public static boolean isOpenSearchTrafficEnabled() {
        ConfigState.State current = state;
        return current != null
                && current.sinks().osEnabled()
                && current.dataSources().contains(ConfigKeys.SRC_TRAFFIC);
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

        String scopeType = incoming.scopeType() == null
                ? ConfigKeys.SCOPE_ALL
                : incoming.scopeType();

        return new ConfigState.State(sources, scopeType, custom, normalizedSinks);
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private static ConfigState.State defaultState() {
        return new ConfigState.State(
                List.of(),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, "")
        );
    }
}