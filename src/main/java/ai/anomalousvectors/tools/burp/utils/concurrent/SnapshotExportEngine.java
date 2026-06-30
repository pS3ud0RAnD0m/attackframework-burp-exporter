package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.IntUnaryOperator;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Parallel snapshot build ({@code build + prepare}) with up to two in-flight bulk flushes.
 *
 * <p>Build workers fill a bounded queue; the assembly thread chunks prepared documents and
 * overlaps chunk flushes with continued queue draining.</p>
 */
public final class SnapshotExportEngine {

    private static final int MAX_BUILD_WORKERS = 4;
    private static final int MAX_IN_FLIGHT_FLUSHES = 2;
    private static final int MIN_QUEUE_CAPACITY = 256;
    private static final int MAX_QUEUE_CAPACITY = 4_096;
    private static final Object POISON = new Object();
    private static final long QUEUE_POLL_MS = 100L;

    private SnapshotExportEngine() {}

    /** Worker count: {@code max(1, min(4, processors - 2))}. */
    public static int defaultBuildWorkers() {
        int processors = Runtime.getRuntime().availableProcessors();
        return Math.max(1, Math.min(MAX_BUILD_WORKERS, processors - 2));
    }

    /**
     * Returns the bounded prepared-document queue capacity for one snapshot run.
     *
     * <p>The queue should be large enough to keep build workers productive while the assembly
     * thread flushes up to two chunks, but bounded so large response bodies cannot accumulate
     * without backpressure.</p>
     *
     * @param buildWorkers requested build worker count
     * @param initialChunkTarget initial chunk target for the snapshot run
     * @return queue capacity in prepared documents
     */
    public static int queueCapacity(int buildWorkers, int initialChunkTarget) {
        int workers = Math.max(1, buildWorkers);
        int chunkTarget = Math.max(1, initialChunkTarget);
        long desired = Math.max((long) MIN_QUEUE_CAPACITY, Math.max(
                (long) workers * MIN_QUEUE_CAPACITY,
                (long) chunkTarget * MAX_IN_FLIGHT_FLUSHES));
        return (int) Math.min(MAX_QUEUE_CAPACITY, desired);
    }

    @FunctionalInterface
    public interface ItemPreparer<T> {
        /**
         * Builds and prepares one snapshot item.
         *
         * @return prepared document, or {@code null} to skip
         */
        PreparedExportDocument prepare(T item);
    }

    /** Observes each flushed chunk (proxy history uses this for route stats and chunk-target tuning). */
    @FunctionalInterface
    public interface ChunkObserver {
        void onChunkFlushed(List<PreparedExportDocument> chunk, BulkPushOutcome outcome, int nextChunkTarget);
    }

    /**
     * Result counters and timings from one parallel snapshot export.
     *
     * @param buildWallMs wall-clock span from worker start until all workers finish
     * @param buildCpuMs aggregate worker build CPU time (sum across workers; may exceed {@code buildWallMs})
     * @param flushMs sum of per-chunk flush wall durations
     * @param fileFlushMs sum of per-chunk file sink durations when recorded
     * @param openSearchFlushMs sum of per-chunk OpenSearch durations when recorded
     */
    public record Result(
            int attempted,
            int success,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int finalChunkTarget,
            int buildWorkers) {

        public Result(
                int attempted,
                int success,
                int chunks,
                long totalChunkBytes,
                long buildWallMs,
                long buildCpuMs,
                long flushMs,
                int finalChunkTarget,
                int buildWorkers) {
            this(
                    attempted,
                    success,
                    chunks,
                    totalChunkBytes,
                    buildWallMs,
                    buildCpuMs,
                    flushMs,
                    -1L,
                    -1L,
                    finalChunkTarget,
                    buildWorkers);
        }
    }

    /**
     * Runs a parallel snapshot export on the calling thread (assembly + flush coordination); build
     * uses background worker threads.
     */
    public static <T> Result run(
            List<T> items,
            int buildWorkers,
            long bulkMaxBytes,
            int initialChunkTarget,
            IntUnaryOperator applyBackpressure,
            ChunkTargetAdjuster adjustChunkTarget,
            String baseUrl,
            String indexName,
            String indexKey,
            ItemPreparer<T> preparer,
            ChunkObserver chunkObserver) {
        if (items == null || items.isEmpty()) {
            return new Result(0, 0, 0, 0L, 0L, 0L, 0L, initialChunkTarget, Math.max(1, buildWorkers));
        }
        int workers = Math.max(1, buildWorkers);
        BlockingQueue<Object> queue = new ArrayBlockingQueue<>(queueCapacity(workers, initialChunkTarget));
        LongAdder buildNanos = new LongAdder();
        long buildWallStartNs = System.nanoTime();
        boolean buildWallEnded = false;
        long buildWallMs = 0L;
        ExecutorService buildPool = Executors.newFixedThreadPool(workers, r -> {
            Thread thread = new Thread(r, "burp-exporter-snapshot-build");
            thread.setDaemon(true);
            return thread;
        });

        for (int worker = 0; worker < workers; worker++) {
            final int workerIndex = worker;
            buildPool.execute(() -> drainWorkerItems(items, workerIndex, workers, preparer, buildNanos, queue));
        }

        ChunkFlushCoordinator flushCoordinator = new ChunkFlushCoordinator(
                baseUrl,
                indexName,
                indexKey,
                applyBackpressure,
                adjustChunkTarget,
                chunkObserver,
                initialChunkTarget);

        int processed = 0;
        int poisonsReceived = 0;
        long estBytes = 0L;
        List<PreparedExportDocument> chunk = new ArrayList<>(initialChunkTarget);

        try {
            while (true) {
                if (!RuntimeConfig.isExportRunning() && chunk.isEmpty() && queue.isEmpty()) {
                    break;
                }
                if (poisonsReceived >= workers && chunk.isEmpty() && queue.isEmpty()) {
                    break;
                }
                Object taken;
                try {
                    taken = queue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (taken == null) {
                    if (poisonsReceived >= workers && !chunk.isEmpty() && queue.isEmpty()) {
                        flushCoordinator.submit(chunk);
                        chunk = new ArrayList<>(flushCoordinator.chunkTarget());
                        estBytes = 0L;
                    }
                    continue;
                }
                if (taken == POISON) {
                    poisonsReceived++;
                    if (!buildWallEnded && poisonsReceived >= workers) {
                        buildWallMs = (System.nanoTime() - buildWallStartNs) / 1_000_000L;
                        buildWallEnded = true;
                    }
                    continue;
                }
                PreparedExportDocument prepared = (PreparedExportDocument) taken;
                SnapshotPacing.paceItem(processed);
                processed++;
                long docBytes = prepared.estimatedBulkBytes();
                boolean countCapReached = chunk.size() >= flushCoordinator.chunkTarget();
                boolean wouldExceedBytes = !chunk.isEmpty() && (estBytes + docBytes) > bulkMaxBytes;
                if (wouldExceedBytes || countCapReached) {
                    flushCoordinator.submit(chunk);
                    chunk = new ArrayList<>(flushCoordinator.chunkTarget());
                    estBytes = 0L;
                }
                chunk.add(prepared);
                estBytes += docBytes;
            }
            if (!chunk.isEmpty()) {
                flushCoordinator.submit(chunk);
            }
            flushCoordinator.awaitAll();
        } finally {
            buildPool.shutdownNow();
            try {
                buildPool.awaitTermination(Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (!buildWallEnded) {
                buildWallMs = (System.nanoTime() - buildWallStartNs) / 1_000_000L;
            }
        }

        long buildCpuMs = buildNanos.sum() / 1_000_000L;
        return new Result(
                flushCoordinator.attempted(),
                flushCoordinator.success(),
                flushCoordinator.chunks(),
                flushCoordinator.totalChunkBytes(),
                buildWallMs,
                buildCpuMs,
                flushCoordinator.flushMs(),
                flushCoordinator.fileFlushMs(),
                flushCoordinator.openSearchFlushMs(),
                flushCoordinator.chunkTarget(),
                workers);
    }

    private static <T> void drainWorkerItems(
            List<T> items,
            int workerIndex,
            int workers,
            ItemPreparer<T> preparer,
            LongAdder buildNanos,
            BlockingQueue<Object> queue) {
        try {
            for (int index = workerIndex; index < items.size(); index += workers) {
                if (!RuntimeConfig.isExportRunning()) {
                    break;
                }
                long buildStartNs = System.nanoTime();
                PreparedExportDocument prepared = preparer.prepare(items.get(index));
                buildNanos.add(System.nanoTime() - buildStartNs);
                if (prepared != null) {
                    queue.put(prepared);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            try {
                queue.put(POISON);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static FlushOutcome flushChunkSync(
            String baseUrl,
            String indexName,
            String indexKey,
            List<PreparedExportDocument> snapshot,
            IntUnaryOperator applyBackpressure,
            ChunkTargetAdjuster adjustChunkTarget,
            int chunkTarget) {
        int adjustedTarget = applyBackpressure == null ? chunkTarget : applyBackpressure.applyAsInt(chunkTarget);
        int attemptedChunk = snapshot.size();
        long chunkBytes = snapshot.stream().mapToLong(document -> document.estimatedBulkBytes()).sum();
        long flushStartNs = System.nanoTime();
        BulkPushOutcome outcome = OpenSearchClientWrapper.pushPreparedBulk(baseUrl, indexName, indexKey, snapshot);
        long chunkFlushMs = (System.nanoTime() - flushStartNs) / 1_000_000L;
        long fileFlushMs = outcome.fileFlushMs();
        long openSearchFlushMs = outcome.openSearchFlushMs();
        if (fileFlushMs < 0L && openSearchFlushMs < 0L) {
            openSearchFlushMs = chunkFlushMs;
        }
        int sent = outcome.successCount();
        int nextTarget = adjustChunkTarget == null
                ? adjustedTarget
                : adjustChunkTarget.adjust(adjustedTarget, attemptedChunk, sent, chunkBytes);
        return new FlushOutcome(
                attemptedChunk, sent, chunkBytes, chunkFlushMs, fileFlushMs, openSearchFlushMs, nextTarget, snapshot, outcome);
    }

    /** Adjusts chunk doc-count target after a flush (proxy history grows/shrinks targets). */
    @FunctionalInterface
    public interface ChunkTargetAdjuster {
        /**
         * @param currentTarget active doc-count target before the flush
         * @param attemptedChunk documents in the flushed chunk
         * @param succeededChunk documents accepted by sinks
         * @param chunkBytes estimated prepared NDJSON bytes in the flushed chunk
         * @return next doc-count target
         */
        int adjust(int currentTarget, int attemptedChunk, int succeededChunk, long chunkBytes);
    }

    private record FlushOutcome(
            int attempted,
            int success,
            long chunkBytes,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int nextChunkTarget,
            List<PreparedExportDocument> snapshot,
            BulkPushOutcome bulkOutcome) {
    }

    private static final class ChunkFlushCoordinator {
        private final String baseUrl;
        private final String indexName;
        private final String indexKey;
        private final IntUnaryOperator applyBackpressure;
        private final ChunkTargetAdjuster adjustChunkTarget;
        private final ChunkObserver chunkObserver;
        private final List<CompletableFuture<FlushOutcome>> inFlight = new ArrayList<>(MAX_IN_FLIGHT_FLUSHES);
        private final TreeMap<Integer, FlushOutcome> completed = new TreeMap<>();
        private int assignSequence;
        private int emitSequence;
        private int chunkTarget;
        private int attempted;
        private int success;
        private int chunks;
        private long totalChunkBytes;
        private long flushMs;
        private long fileFlushMs;
        private long openSearchFlushMs;

        ChunkFlushCoordinator(
                String baseUrl,
                String indexName,
                String indexKey,
                IntUnaryOperator applyBackpressure,
                ChunkTargetAdjuster adjustChunkTarget,
                ChunkObserver chunkObserver,
                int initialChunkTarget) {
            this.baseUrl = baseUrl;
            this.indexName = indexName;
            this.indexKey = indexKey;
            this.applyBackpressure = applyBackpressure;
            this.adjustChunkTarget = adjustChunkTarget;
            this.chunkObserver = chunkObserver;
            this.chunkTarget = initialChunkTarget;
        }

        int chunkTarget() {
            return chunkTarget;
        }

        int attempted() {
            return attempted;
        }

        int success() {
            return success;
        }

        int chunks() {
            return chunks;
        }

        long totalChunkBytes() {
            return totalChunkBytes;
        }

        long flushMs() {
            return flushMs;
        }

        long fileFlushMs() {
            return fileFlushMs;
        }

        long openSearchFlushMs() {
            return openSearchFlushMs;
        }

        /**
         * Hands a completed chunk to the async flusher.
         *
         * <p>The caller must not mutate {@code snapshot} after this call. {@link #run} satisfies
         * that by allocating a fresh chunk list for subsequent documents, which avoids an extra
         * per-chunk defensive copy on large WebSocket/history snapshots.</p>
         */
        void submit(List<PreparedExportDocument> snapshot) {
            if (snapshot.isEmpty()) {
                return;
            }
            while (inFlight.size() >= MAX_IN_FLIGHT_FLUSHES) {
                awaitOldest();
            }
            int currentTarget = chunkTarget;
            int sequence = assignSequence++;
            CompletableFuture<FlushOutcome> future = CompletableFuture.supplyAsync(
                    () -> flushChunkSync(
                            baseUrl, indexName, indexKey, snapshot, applyBackpressure, adjustChunkTarget, currentTarget),
                    SnapshotFlushExecutor.flushExecutor());
            future = future.exceptionally(error -> failureFlushOutcome(snapshot, currentTarget, error));
            inFlight.add(future);
            future.whenComplete((outcome, error) -> {
                if (outcome != null) {
                    synchronized (completed) {
                        completed.put(sequence, outcome);
                    }
                    drainCompleted();
                }
            });
        }

        void awaitAll() {
            while (!inFlight.isEmpty()) {
                awaitOldest();
            }
            drainCompleted();
        }

        private void awaitOldest() {
            inFlight.remove(0).join();
        }

        private void drainCompleted() {
            synchronized (completed) {
                while (completed.containsKey(emitSequence)) {
                    FlushOutcome outcome = completed.remove(emitSequence++);
                    merge(outcome);
                    if (chunkObserver != null) {
                        chunkObserver.onChunkFlushed(outcome.snapshot(), outcome.bulkOutcome(), outcome.nextChunkTarget());
                    }
                    chunkTarget = outcome.nextChunkTarget();
                }
            }
        }

        private void merge(FlushOutcome outcome) {
            attempted += outcome.attempted();
            success += outcome.success();
            totalChunkBytes += outcome.chunkBytes();
            flushMs += outcome.flushMs();
            if (outcome.fileFlushMs() >= 0L) {
                fileFlushMs += outcome.fileFlushMs();
            }
            if (outcome.openSearchFlushMs() >= 0L) {
                openSearchFlushMs += outcome.openSearchFlushMs();
            }
            chunks++;
        }

        private FlushOutcome failureFlushOutcome(
                List<PreparedExportDocument> snapshot,
                int adjustedTarget,
                Throwable error) {
            int attemptedChunk = snapshot.size();
            long chunkBytes = snapshot.stream().mapToLong(document -> document.estimatedBulkBytes()).sum();
            String message = error == null
                    ? "unknown"
                    : (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
            Logger.logWarnPanelOnly("[SnapshotExport] Chunk flush failed for "
                    + indexName + ": " + message);
            BulkPushOutcome bulkOutcome = new BulkPushOutcome(
                    attemptedChunk,
                    0,
                    BulkOutcomeBreakdown.classified(0, attemptedChunk));
            return new FlushOutcome(
                    attemptedChunk,
                    0,
                    chunkBytes,
                    0L,
                    -1L,
                    -1L,
                    adjustedTarget,
                    snapshot,
                    bulkOutcome);
        }
    }
}
