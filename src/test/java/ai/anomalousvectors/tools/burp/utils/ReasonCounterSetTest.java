package ai.anomalousvectors.tools.burp.utils;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link ReasonCounterSet}. */
class ReasonCounterSetTest {

    @Test
    void record_ignoresNullBlankAndNonPositive() {
        ReasonCounterSet set = new ReasonCounterSet();
        set.record(null, 5);
        set.record("", 5);
        set.record("   ", 5);
        set.record("valid", 0);
        set.record("valid", -3);
        assertThat(set.total()).isZero();
        assertThat(set.snapshot()).isEmpty();
    }

    @Test
    void record_trimsKeyAndAccumulates() {
        ReasonCounterSet set = new ReasonCounterSet();
        set.record("scope", 2);
        set.record("  scope  ", 3);
        assertThat(set.get("scope")).isEqualTo(5);
    }

    @Test
    void get_missingOrBlank_returnsZero() {
        ReasonCounterSet set = new ReasonCounterSet();
        set.record("scope", 4);
        assertThat(set.get("missing")).isZero();
        assertThat(set.get(null)).isZero();
        assertThat(set.get("")).isZero();
        assertThat(set.get("  ")).isZero();
    }

    @Test
    void snapshot_isSortedAndImmutableAgainstLaterUpdates() {
        ReasonCounterSet set = new ReasonCounterSet();
        set.record("zeta", 1);
        set.record("alpha", 2);
        set.record("middle", 3);

        Map<String, Long> snap = set.snapshot();

        assertThat(snap.keySet()).containsExactly("alpha", "middle", "zeta");
        assertThat(snap).containsEntry("alpha", 2L).containsEntry("middle", 3L).containsEntry("zeta", 1L);

        set.record("alpha", 100);
        assertThat(snap.get("alpha")).isEqualTo(2L);
        assertThat(set.get("alpha")).isEqualTo(102L);
    }

    @Test
    void total_sumsAllCounters() {
        ReasonCounterSet set = new ReasonCounterSet();
        assertThat(set.total()).isZero();
        set.record("a", 10);
        set.record("b", 20);
        set.record("c", 3);
        assertThat(set.total()).isEqualTo(33);
    }

    @Test
    void clear_removesEverything() {
        ReasonCounterSet set = new ReasonCounterSet();
        set.record("a", 1);
        set.record("b", 2);
        set.clear();
        assertThat(set.total()).isZero();
        assertThat(set.snapshot()).isEmpty();
        assertThat(set.get("a")).isZero();
    }
}
