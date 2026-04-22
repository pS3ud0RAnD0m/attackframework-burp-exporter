package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;

/**
 * Unit tests for {@link SnapshotSummary} that exercise both the traffic-route and
 * index-key baselines and lock down the completion-summary format emitted by
 * {@link SnapshotSummary#logInfo}.
 */
class SnapshotSummaryTest {

    @AfterEach
    void resetStats() {
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
    }

    @Test
    void snapshotRoute_capturesDeltasAcrossMutations() {
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        TrafficRouteBucket.recordOpenSearchSuccess(route, 2);
        TrafficRouteBucket.recordFileSuccess(route, 1);

        SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(route);

        TrafficRouteBucket.recordOpenSearchSuccess(route, 5);
        TrafficRouteBucket.recordOpenSearchFailure(route, 2);
        TrafficRouteBucket.recordFileSuccess(route, 3);
        TrafficRouteBucket.recordFileFailure(route, 4);

        String line = SnapshotSummary.formatSummary("ProxyHistory", baseline, 9, 1234L, true, true);
        assertThat(line).isEqualTo("[ProxyHistory] snapshot complete: captured=9; "
                + "file={success=3, failure=4}; openSearch={success=5, failure=2} in 1234ms.");
    }

    @Test
    void snapshotIndexKey_capturesDeltasAcrossMutations() {
        ExportStats.recordSuccess("sitemap", 1);

        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("sitemap");

        ExportStats.recordSuccess("sitemap", 4);
        ExportStats.recordFailure("sitemap", 1);
        FileExportStats.recordSuccess("sitemap", 3);
        FileExportStats.recordFailure("sitemap", 0);

        String line = SnapshotSummary.formatSummary("Sitemap", baseline, 5, 50L, true, true);
        assertThat(line).isEqualTo("[Sitemap] snapshot complete: captured=5; "
                + "file={success=3, failure=0}; openSearch={success=4, failure=1} in 50ms.");
    }

    @Test
    void formatSummary_omitsFileAndOpenSearchSegmentsWhenInactive() {
        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("sitemap");
        String line = SnapshotSummary.formatSummary("Sitemap", baseline, 7, 12L, false, false);
        assertThat(line).isEqualTo("[Sitemap] snapshot complete: captured=7 in 12ms.");
    }

    @Test
    void formatSummary_clampsNegativesToZero() {
        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("sitemap");
        String line = SnapshotSummary.formatSummary("Sitemap", baseline, -1, -5L, true, true);
        assertThat(line).isEqualTo("[Sitemap] snapshot complete: captured=0; "
                + "file={success=0, failure=0}; openSearch={success=0, failure=0} in 0ms.");
    }

    @Test
    void formatSummary_blankPrefixFallsBackToExport() {
        SnapshotSummary.Baseline baseline = SnapshotSummary.forIndexKey("sitemap");
        String line = SnapshotSummary.formatSummary("  ", baseline, 0, 0L, false, false);
        assertThat(line).startsWith("[Export] snapshot complete: ");
    }

    @Test
    void snapshot_nullOrBlankSource_emitsCapturedOnlyLine() {
        String nullRouteLine = SnapshotSummary.formatSummary(
                "X", SnapshotSummary.forRoute(null), 3, 0L, true, true);
        String blankKeyLine = SnapshotSummary.formatSummary(
                "X", SnapshotSummary.forIndexKey("  "), 3, 0L, true, true);
        // No counter source means deltas stay at zero but segments still render when flags are on.
        assertThat(nullRouteLine).isEqualTo("[X] snapshot complete: captured=3; "
                + "file={success=0, failure=0}; openSearch={success=0, failure=0} in 0ms.");
        assertThat(blankKeyLine).isEqualTo(nullRouteLine);
    }
}
