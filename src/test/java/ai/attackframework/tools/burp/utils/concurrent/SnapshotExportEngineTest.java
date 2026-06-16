package ai.attackframework.tools.burp.utils.concurrent;

import static ai.attackframework.tools.burp.testutils.SnapshotExportEngineTestSupport.fileOnlyTrafficState;
import static ai.attackframework.tools.burp.testutils.SnapshotExportEngineTestSupport.preparedTrafficDoc;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/** Unit tests for {@link SnapshotExportEngine} worker sizing, empty-input behavior, and scale paths. */
class SnapshotExportEngineTest {

    @Test
    void defaultBuildWorkers_isWithinExpectedRange() {
        int workers = SnapshotExportEngine.defaultBuildWorkers();
        assertThat(workers).isBetween(1, 4);
    }

    @Test
    void queueCapacity_scalesWithWorkersAndChunkTargetWithinBounds() {
        assertThat(SnapshotExportEngine.queueCapacity(1, 1)).isEqualTo(256);
        assertThat(SnapshotExportEngine.queueCapacity(4, 250)).isEqualTo(1024);
        assertThat(SnapshotExportEngine.queueCapacity(4, 1500)).isEqualTo(3000);
        assertThat(SnapshotExportEngine.queueCapacity(4, 10_000)).isEqualTo(4096);
    }

    @Test
    void run_emptyItems_returnsZeroCounters() {
        SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                List.of(),
                2,
                5_000_000L,
                250,
                null,
                null,
                "https://opensearch.url:9200",
                "attackframework-test",
                "traffic",
                item -> null,
                null);

        assertThat(result.attempted()).isZero();
        assertThat(result.success()).isZero();
        assertThat(result.chunks()).isZero();
        assertThat(result.buildWallMs()).isZero();
        assertThat(result.buildCpuMs()).isZero();
        assertThat(result.flushMs()).isZero();
        assertThat(result.buildWorkers()).isEqualTo(2);
    }

    @Test
    void run_nullItems_returnsZeroCounters() {
        SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                null,
                1,
                5_000_000L,
                250,
                null,
                null,
                "https://opensearch.url:9200",
                "attackframework-test",
                "traffic",
                unused -> new PreparedExportDocument("idx", "traffic", java.util.Map.of(), 1L, new byte[0]),
                null);

        assertThat(result.attempted()).isZero();
        assertThat(result.buildWorkers()).isEqualTo(1);
    }

    @Test
    void run_largeItemCount_fileOnly_splitsChunksByByteCap() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-byte-cap");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            int itemCount = 2_000;
            long bytesPerDoc = 50_000L;
            List<Integer> items = IntStream.range(0, itemCount).boxed().toList();
            AtomicLong maxObservedChunkBytes = new AtomicLong();

            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    items,
                    2,
                    5L * 1024 * 1024,
                    500,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> preparedTrafficDoc(indexName, item, bytesPerDoc),
                    (chunk, outcome, nextTarget) -> maxObservedChunkBytes.updateAndGet(
                            prev -> Math.max(prev, chunk.stream().mapToLong(PreparedExportDocument::estimatedBulkBytes).sum())));

            int countOnlyChunks = (itemCount + 499) / 500;
            assertThat(result.attempted()).isEqualTo(itemCount);
            assertThat(result.chunks()).isGreaterThan(countOnlyChunks);
            assertThat(maxObservedChunkBytes.get()).isLessThanOrEqualTo(5L * 1024 * 1024);
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void run_moderateItemCount_fileOnly_completesWithExpectedThroughput() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-scale");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            int itemCount = 4_000;
            List<Integer> items = IntStream.range(0, itemCount).boxed().toList();

            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    items,
                    SnapshotExportEngine.defaultBuildWorkers(),
                    5_000_000L,
                    250,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> preparedTrafficDoc(indexName, item, 2_048L),
                    null);

            assertThat(result.attempted()).isEqualTo(itemCount);
            assertThat(result.success()).isEqualTo(itemCount);
            assertThat(result.chunks()).isPositive();
            assertThat(result.buildWallMs()).isPositive();
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }

    @Test
    void run_webSocketScaleHandoff_preservesCompletedChunksWithoutDefensiveCopy() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("snapshot-engine-ws-scale");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);

            String indexName = IndexNaming.indexNameForShortName("traffic");
            int itemCount = 10_000;
            List<Integer> items = IntStream.range(0, itemCount).boxed().toList();
            List<List<PreparedExportDocument>> observedChunks =
                    Collections.synchronizedList(new ArrayList<>());

            SnapshotExportEngine.Result result = SnapshotExportEngine.run(
                    items,
                    SnapshotExportEngine.defaultBuildWorkers(),
                    5_000_000L,
                    250,
                    null,
                    null,
                    "",
                    indexName,
                    "traffic",
                    item -> preparedTrafficDoc(indexName, item, 512L),
                    (chunk, outcome, nextTarget) -> observedChunks.add(chunk));

            int observedDocs = observedChunks.stream().mapToInt(List::size).sum();
            assertThat(result.attempted()).isEqualTo(itemCount);
            assertThat(result.success()).isEqualTo(itemCount);
            assertThat(result.chunks()).isEqualTo(observedChunks.size());
            assertThat(observedDocs).isEqualTo(itemCount);
            assertThat(observedChunks).allSatisfy(chunk -> assertThat(chunk).isNotEmpty());
        } finally {
            ExportReporterLifecycle.resetForTests();
        }
    }
}
