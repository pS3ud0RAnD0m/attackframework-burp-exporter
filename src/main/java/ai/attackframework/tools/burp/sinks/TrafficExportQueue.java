package ai.attackframework.tools.burp.sinks;

import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.ChunkedBulkSender;

/**
 * Bounded queue for traffic documents so the HTTP thread can enqueue and return immediately.
 *
 * <p>A dedicated worker thread drains the queue and pushes via the OpenSearch Bulk API using
 * chunked request body (NDJSON written incrementally; no full batch list in memory). When full,
 * the oldest document is dropped (backpressure). Batches are limited by count
 * ({@link BatchSizeController}), payload size ({@link BulkPayloadEstimator}, 5 MB cap), and time
 * (flush after 100 ms). Used only by the traffic export path.</p>
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

    private TrafficExportQueue() {}

    private static String trafficIndexName() {
        return IndexNaming.indexNameForShortName("traffic");
    }

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
     * @return number of documents currently queued (for stats and tool index)
     */
    public static int getCurrentSize() {
        return queue.size();
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
        if (document == null) return;
        if (!queue.offer(document)) {
            TrafficSpillFileQueue.OfferResult spillResult = spillQueue.offerDetailed(document);
            if (spillResult == TrafficSpillFileQueue.OfferResult.QUEUED) {
                ExportStats.recordTrafficSpillEnqueued(1);
            } else {
                queue.poll();
                ExportStats.recordTrafficQueueDrop(1);
                ExportStats.recordTrafficSpillDrop(1);
                ExportStats.recordTrafficDropReason(
                        spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK
                                ? "spill_low_disk_drop_oldest"
                                : "spill_rejected_drop_oldest",
                        1);
                if (!queue.offer(document)) {
                    // Queue remained full under contention; count as dropped.
                    ExportStats.recordTrafficQueueDrop(1);
                    ExportStats.recordTrafficSpillDrop(1);
                    ExportStats.recordTrafficDropReason("queue_contention_drop", 1);
                    Logger.logError("[TrafficExportQueue] Queue and spill unavailable; dropping traffic document.");
                } else if (spillResult == TrafficSpillFileQueue.OfferResult.REJECTED_LOW_DISK) {
                    Logger.logError("[TrafficExportQueue] Spill disabled by low disk space; used drop-oldest fallback.");
                } else {
                    Logger.logError("[TrafficExportQueue] Spill full; used drop-oldest fallback.");
                }
            }
        }
        startWorkerIfNeeded();
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

    private static void startWorkerIfNeeded() {
        if (workerStarted.compareAndSet(false, true)) {
            Thread t = new Thread(TrafficExportQueue::drainLoop, "attackframework-traffic-export");
            t.setDaemon(true);
            t.start();
        }
    }

    private static void drainLoop() {
        if (!awaitInitialWarmup()) {
            return;
        }
        BatchSizeController batchController = BatchSizeController.getInstance();
        while (true) {
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (!RuntimeConfig.isExportRunning()) {
                clearPendingWork();
                try {
                    TimeUnit.MILLISECONDS.sleep(POLL_TIMEOUT_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                continue;
            }
            if (baseUrl == null || baseUrl.isBlank()) {
                try {
                    Map<String, Object> doc = queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    if (doc != null && RuntimeConfig.isExportRunning()) {
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
            long startNs = System.nanoTime();
            ChunkedBulkSender.Result result = ChunkedBulkSender.push(
                    baseUrl, trafficIndexName(), queue, maxBatch, BULK_MAX_BYTES, BATCH_MAX_WAIT_MS);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000;

            if (result.attemptedCount == 0) {
                continue;
            }
            ExportStats.recordLastPush("traffic", durationMs);
            ExportStats.recordSuccess("traffic", result.successCount);
            ExportStats.recordExportedBytes("traffic", result.successBytes);
            ExportStats.recordTrafficSourceSuccess("proxy_live_http", result.successCount);
            if (result.successCount < result.attemptedCount) {
                long failure = result.attemptedCount - result.successCount;
                ExportStats.recordFailure("traffic", failure);
                ExportStats.recordTrafficSourceFailure("proxy_live_http", failure);
            }
            if (result.isFullSuccess()) {
                batchController.recordSuccess(result.attemptedCount);
            } else {
                batchController.recordFailure(result.attemptedCount);
            }
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

    /**
     * Applies startup grace before first drain while allowing immediate drain under backlog.
     *
     * <p>This keeps the extension responsive at startup when there is little traffic, but avoids
     * fixed-delay throughput penalties during initial backlog loads (for example proxy-history
     * or scanner bursts).</p>
     *
     * @return {@code true} when the worker should continue, {@code false} if interrupted
     */
    private static boolean awaitInitialWarmup() {
        long deadline = System.currentTimeMillis() + STARTUP_GRACE_MAX_MS;
        while (System.currentTimeMillis() < deadline) {
            if (!RuntimeConfig.isExportRunning()) {
                clearPendingWork();
                return true;
            }
            if (queue.size() >= START_DRAIN_BACKLOG_DOCS) {
                return true;
            }
            try {
                long remaining = Math.max(1, deadline - System.currentTimeMillis());
                Map<String, Object> observed = queue.poll(Math.min(STARTUP_POLL_MS, remaining), TimeUnit.MILLISECONDS);
                if (observed != null && RuntimeConfig.isExportRunning()) {
                    queue.offer(observed);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return true;
    }
}
