package ai.attackframework.tools.burp.utils.concurrent;

import static ai.attackframework.tools.burp.testutils.SnapshotExportEngineTestSupport.awaitFlushPoolsIdle;
import static ai.attackframework.tools.burp.testutils.SnapshotExportEngineTestSupport.fileOnlyTrafficState;
import static ai.attackframework.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.TrafficExportQueue;
import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Verifies cooperative Stop/unload behaviour while a large snapshot export is in flight.
 */
@Timeout(60)
class StopDuringSnapshotExportTest {

    private static final int ITEM_COUNT = 2_500;
    private static final long PREPARE_DELAY_NS = 2_000_000L;
    private static final long STOP_JOIN_TIMEOUT_MS = 30_000L;

    @Test
    void run_stopsWithinTimeout_whenExportRunningClearedMidSnapshot() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("stop-during-snapshot-cooperative");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            List<Integer> items = IntStream.range(0, ITEM_COUNT).boxed().toList();
            AtomicInteger preparedCount = new AtomicInteger();
            CountDownLatch preparationStarted = new CountDownLatch(1);
            AtomicReference<SnapshotExportEngine.Result> resultRef = new AtomicReference<>();

            Thread snapshotThread = new Thread(
                    () -> resultRef.set(runSyntheticSnapshot(indexName, items, preparedCount, preparationStarted)),
                    "test-snapshot-cooperative-stop");
            snapshotThread.start();

            assertThat(preparationStarted.await(5, TimeUnit.SECONDS)).isTrue();
            LockSupport.parkNanos(150_000_000L);
            RuntimeConfig.setExportRunning(false);

            snapshotThread.join(STOP_JOIN_TIMEOUT_MS);
            assertThat(snapshotThread.isAlive())
                    .as("snapshot assembly thread must exit after export running is cleared")
                    .isFalse();
            assertThat(preparedCount.get()).isPositive().isLessThan(ITEM_COUNT);
            assertThat(resultRef.get()).isNotNull();
            assertThat(resultRef.get().attempted()).isLessThan(ITEM_COUNT);
            assertThat(awaitFlushPoolsIdle(10_000L))
                    .as("snapshot flush pools must return to idle after cooperative stop")
                    .isTrue();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void lifecycle_stopAndClearPendingExportWork_completesWhileSnapshotRunning() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("stop-during-snapshot-lifecycle");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            List<Integer> items = IntStream.range(0, ITEM_COUNT).boxed().toList();
            AtomicInteger preparedCount = new AtomicInteger();
            CountDownLatch preparationStarted = new CountDownLatch(1);

            Thread snapshotThread = new Thread(
                    () -> runSyntheticSnapshot(indexName, items, preparedCount, preparationStarted),
                    "test-snapshot-lifecycle-stop");
            snapshotThread.start();

            assertThat(preparationStarted.await(5, TimeUnit.SECONDS)).isTrue();
            LockSupport.parkNanos(100_000_000L);

            Thread stopThread = new Thread(ExportReporterLifecycle::stopAndClearPendingExportWork, "test-stop-worker");
            stopThread.start();
            stopThread.join(STOP_JOIN_TIMEOUT_MS);

            snapshotThread.join(STOP_JOIN_TIMEOUT_MS);
            assertThat(stopThread.isAlive()).isFalse();
            assertThat(snapshotThread.isAlive()).isFalse();
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(TrafficExportQueue.getCurrentSize()).isNotNegative();
            assertThat(awaitFlushPoolsIdle(10_000L)).isTrue();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void lifecycle_stopAndClearSessionState_completesWhileSnapshotRunning() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("stop-during-snapshot-unload");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            List<Integer> items = IntStream.range(0, ITEM_COUNT).boxed().toList();
            CountDownLatch preparationStarted = new CountDownLatch(1);

            Thread snapshotThread = new Thread(
                    () -> runSyntheticSnapshot(indexName, items, new AtomicInteger(), preparationStarted),
                    "test-snapshot-unload-stop");
            snapshotThread.start();

            assertThat(preparationStarted.await(5, TimeUnit.SECONDS)).isTrue();
            LockSupport.parkNanos(100_000_000L);

            Thread unloadThread = new Thread(ExportReporterLifecycle::stopAndClearSessionState, "test-unload-worker");
            unloadThread.start();
            unloadThread.join(STOP_JOIN_TIMEOUT_MS);

            snapshotThread.join(STOP_JOIN_TIMEOUT_MS);
            assertThat(unloadThread.isAlive()).isFalse();
            assertThat(snapshotThread.isAlive()).isFalse();
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(awaitFlushPoolsIdle(10_000L)).isTrue();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    private static SnapshotExportEngine.Result runSyntheticSnapshot(
            String indexName,
            List<Integer> items,
            AtomicInteger preparedCount,
            CountDownLatch preparationStarted) {
        return SnapshotExportEngine.run(
                items,
                2,
                5_000_000L,
                250,
                null,
                null,
                "",
                indexName,
                "traffic",
                item -> {
                    preparationStarted.countDown();
                    preparedCount.incrementAndGet();
                    LockSupport.parkNanos(PREPARE_DELAY_NS);
                    return preparedTrafficDoc(indexName, item, 512L);
                },
                null);
    }
}
