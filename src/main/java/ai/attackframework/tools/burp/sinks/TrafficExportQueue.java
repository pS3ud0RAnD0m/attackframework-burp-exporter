package ai.attackframework.tools.burp.sinks;

import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.ChunkedBulkSender;

/**
 * Bounded queue for traffic documents so the HTTP thread can enqueue and return immediately.
 *
 * <p>A dedicated worker thread drains the queue and pushes via the OpenSearch Bulk API using
 * chunked request body (NDJSON written incrementally; no full batch list in memory). When the
 * in-memory queue is full, documents are spilled to a temp-dir file queue; only when spill
 * rejects a document does this path drop the oldest queued item (for example low disk or spill
 * full). Batches are limited by count ({@link BatchSizeController}), payload size
 * ({@link BulkPayloadEstimator}, 5 MB cap), and time (flush after 100 ms). Used by live HTTP
 * and live non-proxy WebSocket export paths.</p>
 */
public final class TrafficExportQueue {

    private static final int CAPACITY = 50_000;
    private static final long POLL_TIMEOUT_MS = 50;
    private static final long BATCH_MAX_WAIT_MS = 100;
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final long STARTUP_GRACE_MAX_MS = 2_000;
    private static final long STARTUP_POLL_MS = 25;
    private static final int START_DRAIN_BACKLOG_DOCS = 64;
    private static final int SPILL_REFILL_TARGET_DOCS = 256;

    private static final LinkedBlockingQueue<Map<String, Object>> queue = new LinkedBlockingQueue<>(CAPACITY);
    private static final TrafficSpillFileQueue spillQueue = new TrafficSpillFileQueue();
    private static final AtomicBoolean workerStarted = new AtomicBoolean(false);
    private static final AtomicLong workerGeneration = new AtomicLong();
    private static final AtomicLong stopThroughGeneration = new AtomicLong();

    /**
     * Reference to the drain worker so shutdown can interrupt and join it deterministically.
     *
     * <p>Single-owner field; swapped under a class lock in {@link #stopWorker()} and lazily
     * recreated by {@link #startWorkerIfNeeded()} on the next {@link #offer(Map)}.</p>
     */
    private static volatile Thread drainWorker;

    /**
     * When {@code true}, {@link #offer(Map)} may queue documents but does not start the drain worker.
     * Used by unit tests that assert in-memory queue depth without racing the background drainer.
     */
    private static volatile boolean drainDisabledForTests;
    private static final long WORKER_GRACEFUL_SHUTDOWN_TIMEOUT_MS = 30_000;
    private static final long WORKER_INTERRUPT_SHUTDOWN_TIMEOUT_MS = 1_000;

    private TrafficExportQueue() {}

    static {
        long recoveredDocs = spillQueue.recoveredCount();
        if (recoveredDocs > 0) {
            long recoveredBytes = spillQueue.recoveredBytes();
            ExportStats.recordTrafficSpillRecovered(recoveredDocs);
            Logger.logInfoPanelOnly("[TrafficExportQueue] Recovered " + recoveredDocs
                    + " spill docs (" + recoveredBytes + " bytes) from " + spillQueue.directoryPath());
        }
    }

    /**
     * Returns the current number of documents in the traffic export queue.
     *
     * @return number of documents currently queued (for stats and Exporter-index observability)
     */
    public static int getCurrentSize() {
        return queue.size();
    }

    /**
     * Suppresses drain-worker startup until reset. For unit tests in this package only.
     *
     * @param disabled {@code true} to keep offers on the in-memory queue without draining
     */
    static void setDrainDisabledForTests(boolean disabled) {
        drainDisabledForTests = disabled;
        if (disabled) {
            stopWorker();
        }
    }

    /**
     * Returns the approximate total bytes of documents currently held in the in-memory queue.
     *
     * <p>Computed on demand by iterating a snapshot of the queue and summing
     * {@link BulkPayloadEstimator#estimateBytes(Map)}. Intended for low-frequency callers
     * (StatsPanel refresh). Does not include spilled documents;
     * those are already tracked as bytes by {@link #getCurrentSpillBytes()}.</p>
     */
    public static long getCurrentBytesEstimate() {
        if (queue.isEmpty()) {
            return 0L;
        }
        long total = 0L;
        for (Map<String, Object> doc : queue) {
            total += BulkPayloadEstimator.estimateBytes(doc);
        }
        return total;
    }

    /** Returns current spill queue depth for StatsPanel observability. */
    public static int getCurrentSpillSize() {
        return spillQueue.size();
    }

    /** Returns current spill queue bytes for StatsPanel observability. */
    public static long getCurrentSpillBytes() {
        return spillQueue.bytes();
    }

    /** Returns oldest spill age in milliseconds (0 when no spilled docs). */
    public static long getCurrentSpillOldestAgeMs() {
        return spillQueue.oldestAgeMs();
    }

    /** Returns startup-recovered spill document count. */
    public static long getRecoveredSpillCount() {
        return spillQueue.recoveredCount();
    }

    /** Returns spill directory path for diagnostics. */
    public static String getSpillDirectoryPath() {
        return spillQueue.directoryPath();
    }

    /**
     * Offers a traffic document to the queue. Non-blocking.
     *
     * <p>If the queue is full, the document is first spilled to disk. Only when spill rejects it
     * does this path fall back to drop-oldest behavior and record a drop in {@link ExportStats}.
     * Starts the drain worker on first use. Thread-safe.</p>
     *
     * @param document the document to enqueue; {@code null} is ignored
     */
    public static void offer(Map<String, Object> document) {
        offerAccepted(document);
    }

    /**
     * Offers a traffic document when export sinks are active.
     *
     * @param document document to enqueue; {@code null} is ignored
     * @return {@code true} when the document was queued or spilled; {@code false} when it was dropped
     */
    public static boolean offerAccepted(Map<String, Object> document) {
        if (document == null) {
            return false;
        }
        if (!isDocumentCurrentlyEnabled(document)) {
            return false;
        }
        if (queue.offer(document)) {
            startWorkerIfNeeded();
            return true;
        }
        TrafficSpillFileQueue.OfferResult spillResult = spillQueue.offerDetailed(document);
        if (spillResult == TrafficSpillFileQueue.OfferResult.QUEUED) {
            ExportStats.recordTrafficSpillEnqueued(1);
            startWorkerIfNeeded();
            return true;
        }
        queue.poll();
        ExportStats.recordTrafficQueueDrop(1);
        ExportStats.recordTrafficSpillDrop(1);
        ExportStats.recordTrafficDropReason(
                spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK
                        ? "spill_low_disk_drop_oldest"
                        : "spill_rejected_drop_oldest",
                1);
        if (!queue.offer(document)) {
            ExportStats.recordTrafficQueueDrop(1);
            ExportStats.recordTrafficSpillDrop(1);
            ExportStats.recordTrafficDropReason("queue_contention_drop", 1);
            Logger.logError("[TrafficExportQueue] Queue and spill unavailable; dropping traffic document.");
            return false;
        }
        if (spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK) {
            Logger.logError("[TrafficExportQueue] Spill disabled by low disk space; used drop-oldest fallback.");
        } else {
            Logger.logError("[TrafficExportQueue] Spill full; used drop-oldest fallback.");
        }
        startWorkerIfNeeded();
        return true;
    }

    /**
     * Clears in-memory and spilled traffic backlog.
     *
     * <p>Used when export is intentionally stopped or a Start attempt fails, so queued traffic
     * does not resume behind a stopped UI.</p>
     */
    public static void clearPendingWork() {
        queue.clear();
        spillQueue.clear();
    }

    /**
     * Removes queued traffic whose route is no longer enabled by the current traffic gate.
     *
     * <p>Used for live config deselection. Stop still calls {@link #clearPendingWork()} because
     * all queued traffic is stale after the run ends.</p>
     *
     * @param gate current runtime traffic gate
     * @return number of queued or spilled documents removed
     */
    public static int purgeDisabledTraffic(RuntimeConfig.TrafficExportGate gate) {
        if (gate == null || !gate.anyTrafficExportEnabled()) {
            int purged = queue.size() + spillQueue.size();
            clearPendingWork();
            return purged;
        }
        AtomicInteger purged = new AtomicInteger();
        queue.removeIf(doc -> {
            boolean remove = !TrafficRouteBucket.isRouteEnabled(TrafficRouteBucket.fromDocument(doc), gate);
            if (remove) {
                purged.incrementAndGet();
            }
            return remove;
        });
        purged.addAndGet(spillQueue.removeIf(
                doc -> !TrafficRouteBucket.isRouteEnabled(TrafficRouteBucket.fromDocument(doc), gate)));
        return purged.get();
    }

    private static void startWorkerIfNeeded() {
        if (drainDisabledForTests) {
            return;
        }
        if (workerStarted.compareAndSet(false, true)) {
            long generation = workerGeneration.incrementAndGet();
            Thread t = new Thread(() -> TrafficExportQueue.drainLoop(generation), "attackframework-traffic-export");
            t.setDaemon(true);
            synchronized (TrafficExportQueue.class) {
                drainWorker = t;
            }
            t.start();
        }
    }

    /**
     * Asks the drain worker to stop after the current batch, then joins it.
     *
     * <p>Safe to call from any thread and safe to call more than once. Resets the start flag so
     * the next {@link #offer(Map)} lazily starts a fresh worker. The normal path does not
     * interrupt the worker: if a bulk request is already in flight, it is allowed to complete.
     * If the worker does not stop within the graceful window, interrupt is used as a bounded
     * fallback so extension unload cannot hang indefinitely.</p>
     */
    public static void stopWorker() {
        long generationToStop = workerGeneration.get();
        stopThroughGeneration.updateAndGet(current -> Math.max(current, generationToStop));
        Thread worker;
        synchronized (TrafficExportQueue.class) {
            worker = drainWorker;
        }
        if (worker != null && worker != Thread.currentThread()) {
            awaitWorker(worker, WORKER_GRACEFUL_SHUTDOWN_TIMEOUT_MS, false);
            if (worker.isAlive()) {
                Logger.logWarnPanelOnly("[TrafficExportQueue] Stop timed out waiting for current batch; interrupting worker.");
                awaitWorker(worker, WORKER_INTERRUPT_SHUTDOWN_TIMEOUT_MS, true);
            }
        }
        if (worker != null && worker.isAlive()) {
            return;
        }
        boolean currentOwner = false;
        synchronized (TrafficExportQueue.class) {
            if (drainWorker == worker) {
                drainWorker = null;
                currentOwner = true;
            }
        }
        if (currentOwner) {
            workerStarted.set(false);
        }
    }

    private static void drainLoop(long generation) {
        try {
            if (!awaitInitialWarmup(generation)) {
                return;
            }
            BatchSizeController batchController = BatchSizeController.getInstance();
            while (true) {
                if (isStopRequested(generation)) {
                    break;
                }
                RuntimeConfig.TrafficExportGate trafficGate = RuntimeConfig.trafficExportGate();
                boolean openSearchEnabled = RuntimeConfig.isOpenSearchTrafficEnabled();
                String baseUrl = openSearchEnabled ? RuntimeConfig.openSearchUrl() : "";
                if (!RuntimeConfig.isExportReady() || !trafficGate.anyTrafficExportEnabled()) {
                    try {
                        TimeUnit.MILLISECONDS.sleep(POLL_TIMEOUT_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    continue;
                }
                if (baseUrl == null || baseUrl.isBlank()) {
                    if (!RuntimeConfig.isAnyFileExportEnabled()) {
                        try {
                            Map<String, Object> doc = queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                            if (doc != null && RuntimeConfig.isExportReady()) {
                                queue.offer(doc);
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                        continue;
                    }
                    int maxBatch = batchController.getCurrentBatchSize();
                    refillFromSpill(Math.max(SPILL_REFILL_TARGET_DOCS, maxBatch));
                    FileOnlyDrainResult result = drainToFileOnly(maxBatch, BULK_MAX_BYTES);
                    if (result.attemptedCount == 0) {
                        continue;
                    }
                    batchController.recordSuccess(result.attemptedCount);
                    continue;
                }

                int maxBatch = batchController.getCurrentBatchSize();
                refillFromSpill(Math.max(SPILL_REFILL_TARGET_DOCS, maxBatch));
                long startNs = System.nanoTime();
                ChunkedBulkSender.Result result = ChunkedBulkSender.push(
                        baseUrl, TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY,
                        queue, maxBatch, BULK_MAX_BYTES, BATCH_MAX_WAIT_MS);
                long durationMs = (System.nanoTime() - startNs) / 1_000_000;

                if (result.attemptedCount == 0) {
                    continue;
                }
                applyBulkOutcome(result, durationMs);
                if (result.isFullSuccess()) {
                    batchController.recordSuccess(result.attemptedCount);
                } else {
                    batchController.recordFailure(result.attemptedCount);
                }
            }
        } finally {
            boolean currentOwner = false;
            synchronized (TrafficExportQueue.class) {
                if (drainWorker == Thread.currentThread()) {
                    drainWorker = null;
                    currentOwner = true;
                }
            }
            if (currentOwner) {
                workerStarted.set(false);
                if (!queue.isEmpty() && RuntimeConfig.isExportReady() && !drainDisabledForTests) {
                    startWorkerIfNeeded();
                }
            }
        }
    }

    private static boolean isStopRequested(long generation) {
        return generation <= stopThroughGeneration.get();
    }

    private static void awaitWorker(Thread worker, long timeoutMs, boolean interrupt) {
        if (interrupt) {
            worker.interrupt();
        }
        try {
            worker.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Applies index-level and per-route accounting for a streaming bulk push outcome.
     *
     * <p>Package-private for unit-test access; production callers invoke it from
     * {@link #drainLoop()} once per completed bulk. Delegates index-level counters and the
     * panel-warn/last-error on partial failure to
     * {@link BulkOutcomeRecorder#record(String, String, String, int, int, boolean)}, then
     * layers per-tool-type and per-source counts derived from {@link ChunkedBulkSender.Result}.
     * {@link BulkOutcomeRecorder} already clamps {@code sent} to {@code [0, attempted]}; the
     * per-route failure maps only apply when the clamped success count is below the attempted
     * total.</p>
     */
    static void applyBulkOutcome(ChunkedBulkSender.Result result, long durationMs) {
        int clampedSent = BulkOutcomeRecorder.record(
                TrafficRouteBucket.INDEX_KEY, "Traffic", "Bulk push",
                result.attemptedCount, result.successCount, true);
        ExportStats.recordLastPush(TrafficRouteBucket.INDEX_KEY, durationMs);
        ExportStats.recordExportedBytes(TrafficRouteBucket.INDEX_KEY, result.successBytes);
        result.trafficToolTypeSuccessCounts.forEach(
                (toolTypeKey, count) -> ExportStats.recordTrafficToolTypeSuccess(toolTypeKey, count.longValue()));
        result.trafficSourceSuccessCounts.forEach(
                (sourceKey, count) -> ExportStats.recordTrafficSourceSuccess(sourceKey, count.longValue()));
        if (clampedSent < result.attemptedCount) {
            result.trafficToolTypeFailureCounts.forEach(
                    (toolTypeKey, count) -> ExportStats.recordTrafficToolTypeFailure(toolTypeKey, count.longValue()));
            result.trafficSourceFailureCounts.forEach(
                    (sourceKey, count) -> ExportStats.recordTrafficSourceFailure(sourceKey, count.longValue()));
        }
    }

    /**
     * Moves a bounded number of spilled docs back to memory queue before sending.
     *
     * <p>Drains only while memory queue has room and stops on first enqueue failure to avoid
     * spinning under contention.</p>
     *
     * @param targetDocs desired minimum queued docs before bulk send
     */
    private static void refillFromSpill(int targetDocs) {
        while (queue.size() < targetDocs) {
            Map<String, Object> spilled = spillQueue.poll();
            if (spilled == null) {
                return;
            }
            if (!isDocumentCurrentlyEnabled(spilled)) {
                continue;
            }
            if (!queue.offer(spilled)) {
                TrafficSpillFileQueue.OfferResult spillResult = spillQueue.offerDetailed(spilled);
                if (spillResult != TrafficSpillFileQueue.OfferResult.QUEUED) {
                    ExportStats.recordTrafficQueueDrop(1);
                    ExportStats.recordTrafficSpillDrop(1);
                    ExportStats.recordTrafficDropReason(
                            spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK
                                    ? "spill_requeue_low_disk_drop"
                                    : "spill_requeue_failed_drop",
                            1);
                    Logger.logError("[TrafficExportQueue] Failed to re-queue drained spill document; dropping.");
                }
                return;
            }
            ExportStats.recordTrafficSpillDequeued(1);
        }
    }

    private static FileOnlyDrainResult drainToFileOnly(int maxBatch, long maxBytes) {
        int attempted = 0;
        long exportedBytes = 0;
        while (attempted < maxBatch && exportedBytes < maxBytes) {
            Map<String, Object> doc;
            try {
                doc = attempted == 0
                        ? queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                        : queue.poll();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (doc == null) {
                break;
            }
            if (!isDocumentCurrentlyEnabled(doc)) {
                continue;
            }
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(
                    TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, doc);
            long docBytes = BulkPayloadEstimator.estimateBytes(prepared.document());
            if (attempted > 0 && exportedBytes + docBytes > maxBytes) {
                queue.offer(doc);
                break;
            }
            FileExportService.emit(prepared);
            attempted++;
            exportedBytes += docBytes;
        }
        return new FileOnlyDrainResult(attempted, exportedBytes);
    }

    static boolean isDocumentCurrentlyEnabled(Map<String, Object> document) {
        RuntimeConfig.TrafficExportGate gate = RuntimeConfig.trafficExportGate();
        return RuntimeConfig.isExportRunning()
                && gate.anyTrafficExportEnabled()
                && TrafficRouteBucket.isRouteEnabled(TrafficRouteBucket.fromDocument(document), gate);
    }

    /**
     * Applies startup grace before first drain while allowing immediate drain under backlog.
     *
     * <p>This keeps the extension responsive at startup when there is little traffic, but avoids
     * fixed-delay throughput penalties during initial backlog loads (for example proxy-history
     * or scanner bursts).</p>
     *
     * @return {@code true} when the worker should continue, {@code false} if interrupted
     */
    private static boolean awaitInitialWarmup(long generation) {
        long deadline = System.currentTimeMillis() + STARTUP_GRACE_MAX_MS;
        while (System.currentTimeMillis() < deadline) {
            if (isStopRequested(generation)) {
                return false;
            }
            if (!RuntimeConfig.isExportReady()) {
                return true;
            }
            if (queue.size() >= START_DRAIN_BACKLOG_DOCS) {
                return true;
            }
            try {
                long remaining = Math.max(1, deadline - System.currentTimeMillis());
                Map<String, Object> observed = queue.poll(Math.min(STARTUP_POLL_MS, remaining), TimeUnit.MILLISECONDS);
                if (observed != null && RuntimeConfig.isExportReady()) {
                    queue.offer(observed);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return true;
    }

    private record FileOnlyDrainResult(int attemptedCount, long exportedBytes) { }
}
