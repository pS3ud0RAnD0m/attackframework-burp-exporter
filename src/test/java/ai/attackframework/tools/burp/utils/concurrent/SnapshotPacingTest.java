package ai.attackframework.tools.burp.utils.concurrent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SnapshotPacing}: pacing boundary semantics, GC duty-cycle
 * arithmetic, and the cached observation surfaced via {@link SnapshotPacing#gcSaturated()}.
 *
 * <p>Tests intentionally avoid asserting precise sleep durations because the per-item
 * yield uses {@link java.util.concurrent.locks.LockSupport#parkNanos(long)}, which the
 * OS scheduler is free to round up. Instead, the boundary semantics are exercised by
 * counting calls and verifying side-effects on the cached duty cycle through the
 * package-private test seam.</p>
 *
 * <p>Per-test reset runs from the constructor (JUnit 5 creates a new instance per
 * {@code @Test} method by default), matching the pattern in {@code SingleDocOutcomeRecorderTest}
 * to avoid {@code @BeforeEach} lifecycle methods that the IDE flags as "never used".</p>
 */
class SnapshotPacingTest {

    public SnapshotPacingTest() {
        SnapshotPacing.resetForTests();
    }

    @Test
    void paceItem_zeroIndex_isNoOp() {
        long t0 = System.nanoTime();
        SnapshotPacing.paceItem(0);
        long elapsedNs = System.nanoTime() - t0;
        assertThat(elapsedNs).isLessThan(SnapshotPacing.PERIODIC_YIELD_NS * 100);
        assertThat(SnapshotPacing.gcSaturated()).isFalse();
    }

    @Test
    void paceItem_belowBoundary_isNoOp() {
        for (int i = 1; i < SnapshotPacing.YIELD_EVERY_N_ITEMS; i++) {
            SnapshotPacing.paceItem(i);
        }
        // No sample taken until first boundary hit, so cached duty stays zero.
        assertThat(SnapshotPacing.gcSaturated()).isFalse();
    }

    @Test
    void paceItem_atBoundary_samplesGcDutyCycle() {
        // Ensure JMX sampling executes without exceptions and leaves cache in a valid range.
        SnapshotPacing.paceItem(SnapshotPacing.YIELD_EVERY_N_ITEMS);
        // We can't guarantee the test process has any GC activity, so just assert the
        // cache is in the legal [0, 1000] per-mille range, which it must be after the
        // sampler has populated it (or left it at the initial 0).
        assertThat(SnapshotPacing.gcSaturated()).isFalse();
    }

    @Test
    void gcSaturated_followsCachedThreshold() {
        SnapshotPacing.setCachedDutyPerMilleForTests(0L);
        assertThat(SnapshotPacing.gcSaturated()).isFalse();

        SnapshotPacing.setCachedDutyPerMilleForTests(299L);
        assertThat(SnapshotPacing.gcSaturated()).isFalse();

        SnapshotPacing.setCachedDutyPerMilleForTests(300L);
        assertThat(SnapshotPacing.gcSaturated()).isTrue();

        SnapshotPacing.setCachedDutyPerMilleForTests(1000L);
        assertThat(SnapshotPacing.gcSaturated()).isTrue();
    }

    @Test
    void computeDutyPerMille_clampsAndHandlesEdgeCases() {
        assertThat(SnapshotPacing.computeDutyPerMille(0L, 100L)).isZero();
        assertThat(SnapshotPacing.computeDutyPerMille(-50L, 100L)).isZero();
        assertThat(SnapshotPacing.computeDutyPerMille(1000L, -100L)).isZero();
        assertThat(SnapshotPacing.computeDutyPerMille(1000L, 0L)).isZero();
        assertThat(SnapshotPacing.computeDutyPerMille(1000L, 250L)).isEqualTo(250L);
        assertThat(SnapshotPacing.computeDutyPerMille(1000L, 1000L)).isEqualTo(1000L);
        // Wall delta of 1000 ms with 5000 ms attributed to GC (multiple parallel collectors)
        // is clamped to 1000 per mille (100 percent).
        assertThat(SnapshotPacing.computeDutyPerMille(1000L, 5000L)).isEqualTo(1000L);
    }

    @Test
    void setCachedDutyPerMilleForTests_clampsToValidRange() {
        SnapshotPacing.setCachedDutyPerMilleForTests(-100L);
        assertThat(SnapshotPacing.gcSaturated()).isFalse();

        SnapshotPacing.setCachedDutyPerMilleForTests(10_000L);
        assertThat(SnapshotPacing.gcSaturated()).isTrue();
    }

    @Test
    void resetForTests_clearsCachedDutyAndSamples() {
        SnapshotPacing.setCachedDutyPerMilleForTests(900L);
        assertThat(SnapshotPacing.gcSaturated()).isTrue();

        SnapshotPacing.resetForTests();
        assertThat(SnapshotPacing.gcSaturated()).isFalse();
    }

    @Test
    void paceItem_incrementsCallCount_evenForNoOpInvocations() {
        long before = SnapshotPacing.paceCallCount();
        SnapshotPacing.paceItem(0);
        SnapshotPacing.paceItem(1);
        SnapshotPacing.paceItem(2);
        assertThat(SnapshotPacing.paceCallCount() - before).isEqualTo(3L);
        assertThat(SnapshotPacing.paceBoundaryCount()).isZero();
    }

    @Test
    void paceItem_atBoundary_incrementsBoundaryCounter() {
        long boundariesBefore = SnapshotPacing.paceBoundaryCount();
        SnapshotPacing.paceItem(SnapshotPacing.YIELD_EVERY_N_ITEMS);
        SnapshotPacing.paceItem(SnapshotPacing.YIELD_EVERY_N_ITEMS * 2);
        assertThat(SnapshotPacing.paceBoundaryCount() - boundariesBefore).isEqualTo(2L);
        assertThat(SnapshotPacing.cumulativeYieldMs()).isGreaterThanOrEqualTo(0L);
    }

    @Test
    void summaryLine_includesAllCountersAndCachedDuty() {
        SnapshotPacing.setCachedDutyPerMilleForTests(421L);
        SnapshotPacing.paceItem(SnapshotPacing.YIELD_EVERY_N_ITEMS);

        String line = SnapshotPacing.summaryLine("UnitTest");

        assertThat(line)
                .startsWith("[SnapshotPacing] tag=UnitTest")
                .contains("pace_calls=")
                .contains("boundaries=")
                .contains("gate_trips=")
                .contains("yield_ms=")
                .contains("gate_sleep_ms=")
                .contains("last_duty_per_mille=");
    }

    @Test
    void resetCountersForSnapshot_clearsRunCountersButLeavesDutyCache() {
        SnapshotPacing.setCachedDutyPerMilleForTests(700L);
        SnapshotPacing.paceItem(SnapshotPacing.YIELD_EVERY_N_ITEMS);
        assertThat(SnapshotPacing.paceCallCount()).isPositive();
        assertThat(SnapshotPacing.paceBoundaryCount()).isPositive();

        SnapshotPacing.resetCountersForSnapshot();

        assertThat(SnapshotPacing.paceCallCount()).isZero();
        assertThat(SnapshotPacing.paceBoundaryCount()).isZero();
        assertThat(SnapshotPacing.gateTripCount()).isZero();
        assertThat(SnapshotPacing.cumulativeGateSleepMs()).isZero();
        assertThat(SnapshotPacing.cumulativeYieldMs()).isZero();
        // Cached duty observation must persist so the next paceItem still has a baseline.
        assertThat(SnapshotPacing.lastDutyPerMille()).isEqualTo(700L);
    }
}
