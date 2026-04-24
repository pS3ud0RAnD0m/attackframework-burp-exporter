package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ExportStatsTest {

    @Test
    void getIndexKeys_returnsAllFiveIndexKeys() {
        List<String> keys = ExportStats.getIndexKeys();
        assertThat(keys).containsExactly("traffic", "exporter", "settings", "sitemap", "findings");
    }

    @Test
    void getIndexKeys_containsExporterAndNotLegacyToolKey() {
        List<String> keys = ExportStats.getIndexKeys();
        assertThat(keys).contains("exporter").doesNotContain("tool");
    }

    @Test
    void recordSuccess_incrementsCountAndTotal() {
        long before = ExportStats.getSuccessCount("traffic");
        ExportStats.recordSuccess("traffic", 3);
        assertThat(ExportStats.getSuccessCount("traffic")).isEqualTo(before + 3);

        long totalBefore = ExportStats.getTotalSuccessCount();
        ExportStats.recordSuccess("findings", 2);
        assertThat(ExportStats.getTotalSuccessCount()).isEqualTo(totalBefore + 2);
    }

    @Test
    void recordFailure_incrementsCountAndTotal() {
        long before = ExportStats.getFailureCount("sitemap");
        ExportStats.recordFailure("sitemap", 1);
        assertThat(ExportStats.getFailureCount("sitemap")).isEqualTo(before + 1);

        long totalBefore = ExportStats.getTotalFailureCount();
        ExportStats.recordFailure("exporter", 1);
        assertThat(ExportStats.getTotalFailureCount()).isEqualTo(totalBefore + 1);
    }

    @Test
    void recordPermanentDrop_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getPermanentDrops("traffic");
        long beforeTotal = ExportStats.getTotalPermanentDrops();
        ExportStats.recordPermanentDrop("traffic", 3);
        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(beforeTraffic + 3);
        assertThat(ExportStats.getTotalPermanentDrops()).isEqualTo(beforeTotal + 3);
    }

    @Test
    void recordPermanentDrop_withZeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getPermanentDrops("sitemap");
        ExportStats.recordPermanentDrop("sitemap", 0);
        ExportStats.recordPermanentDrop("sitemap", -5);
        assertThat(ExportStats.getPermanentDrops("sitemap")).isEqualTo(before);
    }

    @Test
    void recordExportedBytes_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getExportedBytes("traffic");
        long beforeTotal = ExportStats.getTotalExportedBytes();
        ExportStats.recordExportedBytes("traffic", 2048);
        assertThat(ExportStats.getExportedBytes("traffic")).isEqualTo(beforeTraffic + 2048);
        assertThat(ExportStats.getTotalExportedBytes()).isEqualTo(beforeTotal + 2048);
    }

    @Test
    void recordSuccess_withZeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getSuccessCount("settings");
        ExportStats.recordSuccess("settings", 0);
        ExportStats.recordSuccess("settings", -1);
        assertThat(ExportStats.getSuccessCount("settings")).isEqualTo(before);
    }

    @Test
    void recordLastPush_setsDuration() {
        ExportStats.recordLastPush("traffic", 150);
        assertThat(ExportStats.getLastPushDurationMs("traffic")).isEqualTo(150);
    }

    @Test
    void recordLastError_setsAndTruncatesError() {
        ExportStats.recordLastError("traffic", "short");
        assertThat(ExportStats.getLastError("traffic")).isEqualTo("short");

        String longMsg = "a".repeat(300);
        ExportStats.recordLastError("traffic", longMsg);
        String got = ExportStats.getLastError("traffic");
        assertThat(got).endsWith("...");
        assertThat(got.length()).isLessThanOrEqualTo(203);

        ExportStats.recordLastError("traffic", null);
        assertThat(ExportStats.getLastError("traffic")).isNull();
        ExportStats.recordLastError("traffic", "");
        assertThat(ExportStats.getLastError("traffic")).isNull();
    }

    @Test
    void getters_forUnknownIndex_returnsZeroOrNull() {
        String unknown = "unknown-index-key";
        assertThat(ExportStats.getSuccessCount(unknown)).isEqualTo(0);
        assertThat(ExportStats.getFailureCount(unknown)).isEqualTo(0);
        assertThat(ExportStats.getLastPushDurationMs(unknown)).isEqualTo(-1);
        assertThat(ExportStats.getLastError(unknown)).isNull();
    }

    @Test
    void getQueueSize_returnsNonNegativeForEachIndexKey() {
        for (String indexKey : ExportStats.getIndexKeys()) {
            int size = ExportStats.getQueueSize(indexKey);
            assertThat(size).isGreaterThanOrEqualTo(0);
        }
    }

    @Test
    void recordTrafficQueueDrop_incrementsAndGetTrafficQueueDrops_returnsValue() {
        long before = ExportStats.getTrafficQueueDrops();
        ExportStats.recordTrafficQueueDrop(1);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(before + 1);
        ExportStats.recordTrafficQueueDrop(3);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(before + 4);
    }

    @Test
    void recordTrafficQueueDrop_zeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getTrafficQueueDrops();
        ExportStats.recordTrafficQueueDrop(0);
        ExportStats.recordTrafficQueueDrop(-1);
        assertThat(ExportStats.getTrafficQueueDrops()).isEqualTo(before);
    }

    @Test
    void recordTrafficToolSourceFallback_incrementsCounter() {
        long before = ExportStats.getTrafficToolSourceFallbacks();
        ExportStats.recordTrafficToolSourceFallback();
        ExportStats.recordTrafficToolSourceFallback();
        assertThat(ExportStats.getTrafficToolSourceFallbacks()).isEqualTo(before + 2);
    }

    @Test
    void trafficSpillCounters_recordAndReadTotals() {
        long enqueuedBefore = ExportStats.getTrafficSpillEnqueued();
        long dequeuedBefore = ExportStats.getTrafficSpillDequeued();
        long droppedBefore = ExportStats.getTrafficSpillDrops();
        long recoveredBefore = ExportStats.getTrafficSpillRecovered();
        long prunedBefore = ExportStats.getTrafficSpillExpiredPruned();
        long reasonBefore = ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest");

        ExportStats.recordTrafficSpillEnqueued(3);
        ExportStats.recordTrafficSpillDequeued(2);
        ExportStats.recordTrafficSpillDrop(1);
        ExportStats.recordTrafficSpillRecovered(4);
        ExportStats.recordTrafficSpillExpiredPruned(5);
        ExportStats.recordTrafficDropReason("spill_rejected_drop_oldest", 6);

        assertThat(ExportStats.getTrafficSpillEnqueued()).isEqualTo(enqueuedBefore + 3);
        assertThat(ExportStats.getTrafficSpillDequeued()).isEqualTo(dequeuedBefore + 2);
        assertThat(ExportStats.getTrafficSpillDrops()).isEqualTo(droppedBefore + 1);
        assertThat(ExportStats.getTrafficSpillRecovered()).isEqualTo(recoveredBefore + 4);
        assertThat(ExportStats.getTrafficSpillExpiredPruned()).isEqualTo(prunedBefore + 5);
        assertThat(ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest")).isEqualTo(reasonBefore + 6);
    }

    @Test
    void recordRetryQueueDrop_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getRetryQueueDrops("traffic");
        long beforeExporter = ExportStats.getRetryQueueDrops("exporter");
        long beforeTotal = ExportStats.getTotalRetryQueueDrops();
        ExportStats.recordRetryQueueDrop("traffic", 2);
        assertThat(ExportStats.getRetryQueueDrops("traffic")).isEqualTo(beforeTraffic + 2);
        assertThat(ExportStats.getTotalRetryQueueDrops()).isEqualTo(beforeTotal + 2);
        ExportStats.recordRetryQueueDrop("exporter", 1);
        assertThat(ExportStats.getRetryQueueDrops("exporter")).isEqualTo(beforeExporter + 1);
        assertThat(ExportStats.getTotalRetryQueueDrops()).isEqualTo(beforeTotal + 3);
    }

    @Test
    void recordRetryQueueDrop_zeroOrNegative_doesNotChangeCount() {
        long before = ExportStats.getRetryQueueDrops("sitemap");
        ExportStats.recordRetryQueueDrop("sitemap", 0);
        ExportStats.recordRetryQueueDrop("sitemap", -1);
        assertThat(ExportStats.getRetryQueueDrops("sitemap")).isEqualTo(before);
    }

    @Test
    void recordOpenSearchSuccess_updatesLastSuccessAndResetsConsecutiveFailures() {
        ExportStats.resetForTests();
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isEqualTo(-1L);
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(0L);

        ExportStats.recordOpenSearchFailure();
        ExportStats.recordOpenSearchFailure();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(2L);

        long beforeSuccess = System.currentTimeMillis();
        ExportStats.recordOpenSearchSuccess();
        assertThat(ExportStats.getOpenSearchConsecutiveFailures()).isEqualTo(0L);
        assertThat(ExportStats.getOpenSearchLastSuccessAtMs()).isGreaterThanOrEqualTo(beforeSuccess);
    }

    @Test
    void recordSkipReason_incrementsPerReasonAndTotal_andIgnoresBlankOrZero() {
        ExportStats.resetForTests();
        ExportStats.recordSkipReason("scope", 3);
        ExportStats.recordSkipReason("tool_disabled", 1);
        ExportStats.recordSkipReason(null, 5);
        ExportStats.recordSkipReason("  ", 2);
        ExportStats.recordSkipReason("scope", 0);
        ExportStats.recordSkipReason("scope", -4);

        assertThat(ExportStats.getSkipReasonCount("scope")).isEqualTo(3);
        assertThat(ExportStats.getSkipReasonCount("tool_disabled")).isEqualTo(1);
        assertThat(ExportStats.getTotalSkipCount()).isEqualTo(4);

        Map<String, Long> counts = ExportStats.getSkipReasonCounts();
        assertThat(counts).containsEntry("scope", 3L).containsEntry("tool_disabled", 1L);
    }

    @Test
    void getOldestQueuedAgeMs_withEmptyQueue_returnsMinusOne() {
        ExportStats.resetForTests();
        for (String indexKey : ExportStats.getIndexKeys()) {
            assertThat(ExportStats.getOldestQueuedAgeMs(indexKey)).isEqualTo(-1L);
        }
    }

    @Test
    void getThroughputDocsPerSecLast60s_afterRecordSuccess_reflectsCount() {
        ExportStats.recordSuccess("traffic", 60);
        double t = ExportStats.getThroughputDocsPerSecLast60s();
        assertThat(t).isGreaterThanOrEqualTo(1.0);
    }

    @Test
    void getThroughputDocsPerSecLast60s_returnsNonNegative() {
        assertThat(ExportStats.getThroughputDocsPerSecLast60s()).isGreaterThanOrEqualTo(0.0);
    }

    @Test
    void recordSuccess_zeroOrNegative_doesNotAffectThroughput() {
        double before = ExportStats.getThroughputDocsPerSecLast60s();
        ExportStats.recordSuccess("traffic", 0);
        ExportStats.recordSuccess("traffic", -1);
        assertThat(ExportStats.getThroughputDocsPerSecLast60s()).isEqualTo(before);
    }

    @Test
    void recordExportStartRequested_thenTrafficSuccess_setsStartToFirstTrafficMetric() {
        ExportStats.recordExportStartRequested();
        assertThat(ExportStats.getStartToFirstTrafficMs()).isEqualTo(-1);
        ExportStats.recordSuccess("traffic", 1);
        assertThat(ExportStats.getStartToFirstTrafficMs()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void recordProxyHistorySnapshot_storesLatestSnapshotStats() {
        ExportStats.recordProxyHistorySnapshot(200, 190, 4000, 300);
        ExportStats.ProxyHistorySnapshotStats s = ExportStats.getLastProxyHistorySnapshot();
        assertThat(s).isNotNull();
        assertThat(s.attempted()).isEqualTo(200);
        assertThat(s.success()).isEqualTo(190);
        assertThat(s.durationMs()).isEqualTo(4000);
        assertThat(s.finalChunkTarget()).isEqualTo(300);
        assertThat(s.docsPerSecond()).isGreaterThan(0.0);
    }

    @Test
    void trafficSourceStats_recordAndRead_bySourceKey() {
        long liveSuccessBefore = ExportStats.getTrafficSourceSuccessCount("proxy_live_http");
        long liveFailureBefore = ExportStats.getTrafficSourceFailureCount("proxy_live_http");
        ExportStats.recordTrafficSourceSuccess("proxy_live_http", 5);
        ExportStats.recordTrafficSourceFailure("proxy_live_http", 2);
        assertThat(ExportStats.getTrafficSourceSuccessCount("proxy_live_http"))
                .isEqualTo(liveSuccessBefore + 5);
        assertThat(ExportStats.getTrafficSourceFailureCount("proxy_live_http"))
                .isEqualTo(liveFailureBefore + 2);
    }
}
