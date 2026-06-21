package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/** Unit tests for {@link StatsClipboardSnapshot}. */
class StatsClipboardSnapshotTest {

    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level)) {
            infoMessages.add(message);
        }
    };

    private ConfigState.State previousState;

    @BeforeEach
    void setUp() {
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
    void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        if (previousState != null) {
            RuntimeConfig.updateState(previousState);
        }
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
}
