package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

class RuntimeConfigDestinationGatingTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void restoreRuntimeState() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void openSearchUrl_returnsBlank_whenDestinationDisabledEvenIfUrlIsSaved() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isAnyFileExportEnabled()).isTrue();
            assertThat(RuntimeConfig.isAnySinkEnabled()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.openSearchUrl()).isEmpty();
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void isOpenSearchTrafficEnabled_isFalse_whenOnlyFileTrafficExportIsConfigured() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isAnyTrafficExportEnabled()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchTrafficEnabled()).isFalse();
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void isOpenSearchExportEnabled_isTrue_whenDestinationAndUrlAreConfigured() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(RuntimeConfig.openSearchUrl()).isEqualTo("https://opensearch.url:9200");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void activeSinkSummary_reportsEnabledDestinations() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files and OpenSearch");

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("OpenSearch");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void disableOpenSearchDestination_staysStickyUntilExportStops() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);

            assertThat(RuntimeConfig.disableOpenSearchDestination()).isTrue();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchDisabledForCurrentRun()).isTrue();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files");

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isFalse();
            assertThat(RuntimeConfig.openSearchUrl()).isEmpty();

            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "/path/to/directory", false, true,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null
            ));

            assertThat(RuntimeConfig.isOpenSearchDisabledForCurrentRun()).isFalse();
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(RuntimeConfig.activeSinkSummary()).isEqualTo("Files and OpenSearch");
        } finally {
            restoreRuntimeState();
        }
    }

    @Test
    void prepareIndexNamesForCurrentRun_keepsResolvedNamesStable_untilExportStops() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    "${now:yyyyMMdd}-attackframework-tool-burp",
                    null));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);

            assertThat(RuntimeConfig.prepareIndexNamesForCurrentRun().valid()).isTrue();
            String toolDuringRun = RuntimeConfig.indexNameForKey("tool");
            String trafficDuringRun = RuntimeConfig.indexNameForKey("traffic");
            Instant resolvedAt = RuntimeConfig.resolvedIndexNamesAt();

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    "changed-base",
                    null));

            assertThat(RuntimeConfig.indexNameForKey("tool")).isEqualTo(toolDuringRun);
            assertThat(RuntimeConfig.indexNameForKey("traffic")).isEqualTo(trafficDuringRun);
            assertThat(RuntimeConfig.resolvedIndexNamesAt()).isEqualTo(resolvedAt);

            RuntimeConfig.setExportRunning(false);
            assertThat(RuntimeConfig.indexNameForKey("tool")).isEqualTo("changed-base-exporter");
            assertThat(RuntimeConfig.indexNameForKey("traffic")).isEqualTo("changed-base-traffic");
        } finally {
            restoreRuntimeState();
        }
    }
}
