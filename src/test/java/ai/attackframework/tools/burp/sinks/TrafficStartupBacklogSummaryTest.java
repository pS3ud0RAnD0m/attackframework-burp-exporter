package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/** Unit tests for {@link TrafficStartupBacklogSummary}. */
class TrafficStartupBacklogSummaryTest {

    @AfterEach
    void tearDown() {
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void hasExpectedStartupComponents_falseAfterClearRunState() {
        TrafficStartupBacklogSummary.startForCurrentRun();
        TrafficStartupBacklogSummary.clearRunState();
        assertThat(TrafficStartupBacklogSummary.hasExpectedStartupComponents()).isFalse();
    }

    @Test
    void complete_afterClearRunState_isIgnored() {
        TrafficStartupBacklogSummary.startForCurrentRun();
        TrafficStartupBacklogSummary.clearRunState();
        SnapshotSummary.Baseline baseline =
                SnapshotSummary.forRoute(TrafficRouteBucket.proxyHistorySnapshot());

        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_HISTORY, 100, baseline);
    }

    @Test
    void complete_whenExportNotRunning_isIgnored() {
        TrafficStartupBacklogSummary.startForCurrentRun();
        RuntimeConfig.setExportRunning(false);
        SnapshotSummary.Baseline baseline =
                SnapshotSummary.forRoute(TrafficRouteBucket.proxyHistorySnapshot());

        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_HISTORY, 100, baseline);
    }

    @Test
    void formatCompletionLine_sumsTrafficStartupComponents() {
        String line = TrafficStartupBacklogSummary.formatCompletionLineForTests(
                Map.of(
                        TrafficStartupBacklogSummary.Component.REPEATER_TABS,
                        result(15, 15, 0, 15, 0),
                        TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                        result(117, 117, 0, 117, 0),
                        TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                        result(26_838, 26_838, 0, 26_838, 0)),
                true,
                true);

        assertThat(line).isEqualTo("[StartupExport] Traffic: backlog complete captured=26970; "
                + "file={written=26970, failure=0}; openSearch={exported=26970, failure=0}; "
                + "components={repeater_tabs=15, proxy_websocket=117, proxy_history=26838}.");
    }

    private static TrafficStartupBacklogSummary.ComponentResult result(
            int captured,
            long fileSuccess,
            long fileFailure,
            long openSearchSuccess,
            long openSearchFailure) {
        return new TrafficStartupBacklogSummary.ComponentResult(
                captured,
                new SnapshotSummary.CompletionDeltas(
                        fileSuccess,
                        fileFailure,
                        openSearchSuccess,
                        openSearchFailure));
    }
}
