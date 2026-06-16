package ai.attackframework.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/** Tests throttled aggregation for high-volume export pressure logs. */
class ExportPressureLogThrottlerTest {

    @Test
    void record_emitsFirstEventImmediatelyAndThenThrottlesCumulativeSummaries() {
        AtomicLong now = new AtomicLong(1_000L);
        List<String> logs = new ArrayList<>();
        ExportPressureLogThrottler throttler = new ExportPressureLogThrottler(
                "TestPressure", 30_000L, now::get, logs::add);

        throttler.record("spill queued", 1, () -> "queue_depth=50000");
        throttler.record("spill queued", 999, () -> "queue_depth=50000");
        throttler.record("drop-oldest", 2, () -> "queue_depth=50000");

        assertThat(logs).hasSize(1);
        assertThat(logs.getFirst())
                .contains("[TestPressure] Overflow summary")
                .contains("spill_queued=1")
                .contains("queue_depth=50000");

        now.addAndGet(30_000L);
        throttler.record("spill queued", 1, () -> "queue_depth=49999");

        assertThat(logs).hasSize(2);
        assertThat(logs.get(1))
                .contains("drop-oldest=2")
                .contains("spill_queued=1001")
                .contains("queue_depth=49999");
    }
}
