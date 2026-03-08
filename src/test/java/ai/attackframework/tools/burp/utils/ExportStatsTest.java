package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ExportStatsTest {

    @Test
    void getIndexKeys_returnsAllFiveIndexKeys() {
        List<String> keys = ExportStats.getIndexKeys();
        assertThat(keys).containsExactly("traffic", "tool", "settings", "sitemap", "findings");
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
        ExportStats.recordFailure("tool", 1);
        assertThat(ExportStats.getTotalFailureCount()).isEqualTo(totalBefore + 1);
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
    void recordRetryQueueDrop_incrementsPerIndexAndTotal() {
        long beforeTraffic = ExportStats.getRetryQueueDrops("traffic");
        long beforeTool = ExportStats.getRetryQueueDrops("tool");
        long beforeTotal = ExportStats.getTotalRetryQueueDrops();
        ExportStats.recordRetryQueueDrop("traffic", 2);
        assertThat(ExportStats.getRetryQueueDrops("traffic")).isEqualTo(beforeTraffic + 2);
        assertThat(ExportStats.getTotalRetryQueueDrops()).isEqualTo(beforeTotal + 2);
        ExportStats.recordRetryQueueDrop("tool", 1);
        assertThat(ExportStats.getRetryQueueDrops("tool")).isEqualTo(beforeTool + 1);
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
}
