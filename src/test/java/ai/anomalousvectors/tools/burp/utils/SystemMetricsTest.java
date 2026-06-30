package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Sanity coverage for {@link SystemMetrics#snapshot()}.
 *
 * <p>JMX values are JVM-dependent, so the test just pins the invariants the rest of the
 * codebase relies on: heap is non-negative, {@code used <= committed <= max}, and the
 * "available" buffer-pool fields are either non-negative or the explicit {@code -1}
 * sentinel.</p>
 */
class SystemMetricsTest {

    @Test
    void snapshot_heapValuesAreOrdered_andCommittedExposed() {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();

        assertThat(snapshot.heapUsedBytes()).isGreaterThanOrEqualTo(0L);
        assertThat(snapshot.heapCommittedBytes())
                .as("committed heap must be at least heap used")
                .isGreaterThanOrEqualTo(snapshot.heapUsedBytes());
        assertThat(snapshot.heapMaxBytes())
                .as("max heap must be at least committed")
                .isGreaterThanOrEqualTo(snapshot.heapCommittedBytes());
    }

    @Test
    void snapshot_bufferPoolFields_areNonNegativeOrMinusOneSentinel() {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();
        assertThat(snapshot.directBufferUsedBytes()).isGreaterThanOrEqualTo(-1L);
        assertThat(snapshot.mappedBufferUsedBytes()).isGreaterThanOrEqualTo(-1L);
    }

    @Test
    void snapshot_threadCounts_areConsistent() {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();
        assertThat(snapshot.threadCount()).isGreaterThan(0);
        assertThat(snapshot.peakThreadCount()).isGreaterThanOrEqualTo(snapshot.threadCount());
    }
}
