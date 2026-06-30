package ai.anomalousvectors.tools.burp.utils.concurrent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/** Regression tests for snapshot flush pool separation. */
class SnapshotFlushExecutorTest {

    @Test
    void nestedDualSinkOnSeparatePool_completesWithoutDeadlock() throws Exception {
        AtomicInteger dualSinkTasksCompleted = new AtomicInteger();

        Runnable dualSinkStyleWork =
                () -> {
                    CompletableFuture<Void> file =
                            CompletableFuture.runAsync(
                                    dualSinkTasksCompleted::incrementAndGet,
                                    SnapshotFlushExecutor.dualSinkExecutor());
                    CompletableFuture<Void> openSearch =
                            CompletableFuture.runAsync(
                                    dualSinkTasksCompleted::incrementAndGet,
                                    SnapshotFlushExecutor.dualSinkExecutor());
                    CompletableFuture.allOf(file, openSearch).join();
                };

        CompletableFuture<Void> flushOne =
                CompletableFuture.runAsync(dualSinkStyleWork, SnapshotFlushExecutor.flushExecutor());
        CompletableFuture<Void> flushTwo =
                CompletableFuture.runAsync(dualSinkStyleWork, SnapshotFlushExecutor.flushExecutor());

        CompletableFuture.allOf(flushOne, flushTwo).get(10, TimeUnit.SECONDS);
        assertThat(dualSinkTasksCompleted.get()).isEqualTo(4);
    }

    @Test
    void stats_reportsFlushAndDualSinkPoolPressure() {
        SnapshotFlushExecutor.Snapshot stats = SnapshotFlushExecutor.stats();

        assertThat(stats.flush().poolSize()).isGreaterThanOrEqualTo(0);
        assertThat(stats.flush().queueSize()).isGreaterThanOrEqualTo(0);
        assertThat(stats.dualSink().poolSize()).isGreaterThanOrEqualTo(0);
        assertThat(stats.dualSink().queueSize()).isGreaterThanOrEqualTo(0);
    }
}
