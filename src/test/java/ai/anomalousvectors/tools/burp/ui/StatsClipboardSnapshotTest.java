package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/** Unit tests for {@link StatsClipboardSnapshot}. */
class StatsClipboardSnapshotTest {

    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final List<String> warnMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level)) {
            infoMessages.add(message);
        } else if ("WARN".equals(level)) {
            warnMessages.add(message);
        }
    };

    private ConfigState.State previousState;

    @BeforeEach
    public void setUp() {
        ConfigPanel.shutdownStartupExecutor();
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
        previousState = RuntimeConfig.getState();
        RuntimeConfig.updateState(new ConfigState.State(
                java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                java.util.List.of(),
                new ConfigState.Sinks(true, "/tmp/export", true, false,
                        true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        ExportStats.recordSuccess("traffic", 100);
        FileExportStats.recordSuccess("traffic", 101);
        ExportStats.recordBodyEnumerationMisgateSuspect();
    }

    @AfterEach
    public void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        StatsClipboardSnapshot.setOpenSearchCountResolverForTests(null);
        if (previousState != null) {
            RuntimeConfig.updateState(previousState);
        }
        ConfigPanel.shutdownStartupExecutor();
    }

    @Test
    void buildClipboardText_includesFileOpenSearchTablesAndParameterIntegrity() {
        String text = StatsClipboardSnapshot.buildClipboardText();

        assertThat(text).contains("File Counts");
        assertThat(text).contains("OpenSearch Counts");
        assertThat(text).contains("Misc Stats");
        assertThat(text).contains("Traffic\t101");
        assertThat(text).contains("Traffic\t100");
        assertThat(text).contains("Mis-gate Suspects: 1");
        assertThat(text).contains("Export Running: No");
    }

    @Test
    void logSessionStopSummary_emitsThreeSingleLineJsonEntries() throws Exception {
        StatsClipboardSnapshot.logSessionStopSummary();
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(infoMessages).hasSize(3);
        assertThat(infoMessages.get(0)).startsWith("[Stats] Session stop {\"kind\":\"file_counts\"");
        assertThat(infoMessages.get(1)).startsWith("[Stats] Session stop {\"kind\":\"open_search_counts\"");
        assertThat(infoMessages.get(2)).startsWith("[Stats] Session stop {\"kind\":\"misc_stats\"");
        for (String line : infoMessages) {
            assertThat(line).doesNotContain("\n").doesNotContain("\r");
            assertThat(line).contains("\"kind\":");
        }
        assertThat(infoMessages.get(2)).contains("Mis-gate Suspects");
    }

    @Test
    void logSessionStopSummaryWithOpenSearchCounts_usesResolvedIndexCounts() throws Exception {
        StatsClipboardSnapshot.setOpenSearchCountResolverForTests(keys -> Map.of("traffic", 123L));

        StatsClipboardSnapshot.logSessionStopSummaryWithOpenSearchCounts();
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(infoMessages).hasSize(4);
        assertThat(infoMessages.get(0))
                .contains("[Stats] Collecting final OpenSearch counts via refresh/_count for indexes:")
                .contains("tool-burp-traffic");
        assertThat(infoMessages.get(2))
                .contains("\"count_source\":\"opensearch_index_count\"")
                .contains("[\"Traffic\",\"123\"");
        assertThat(warnMessages).isEmpty();
    }

    @Test
    void logSessionStopSummaryWithOpenSearchCounts_fallsBackToSessionCountersWhenCountFails() throws Exception {
        StatsClipboardSnapshot.setOpenSearchCountResolverForTests(keys -> {
            throw new IllegalStateException("cluster unavailable");
        });

        StatsClipboardSnapshot.logSessionStopSummaryWithOpenSearchCounts();
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(warnMessages)
                .anySatisfy(message -> assertThat(message)
                        .contains("[Stats] Session stop OpenSearch index counts unavailable at Stop")
                        .contains("cluster unavailable"));
        assertThat(infoMessages).hasSize(4);
        assertThat(infoMessages.get(0))
                .contains("[Stats] Collecting final OpenSearch counts via refresh/_count for indexes:")
                .contains("tool-burp-traffic");
        assertThat(infoMessages.get(2))
                .contains("\"count_source\":\"session_export_counters\"")
                .contains("\"count_warning\":\"OpenSearch index counts unavailable at Stop; using session export counters")
                .contains("[\"Traffic\",\"100\"");
    }
}
