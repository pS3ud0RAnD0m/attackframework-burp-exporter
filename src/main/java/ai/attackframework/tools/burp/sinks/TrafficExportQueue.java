package ai.attackframework.tools.burp.sinks;

import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
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

    private static final String TRAFFIC_INDEX = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final int CAPACITY = 50_000;
    private static final long POLL_TIMEOUT_MS = 50;
    private static final long BATCH_MAX_WAIT_MS = 100;
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final long STARTUP_GRACE_MAX_MS = 2_000;
    private static final long STARTUP_POLL_MS = 25;
    private static final int START_DRAIN_BACKLOG_DOCS = 64;

    private static final LinkedBlockingQueue<Map<String, Object>> queue = new LinkedBlockingQueue<>(CAPACITY);
    private static final AtomicBoolean workerStarted = new AtomicBoolean(false);

    private TrafficExportQueue() {}

    /**
     * Returns the current number of documents in the traffic export queue.
     *
     * @return number of documents currently queued (for stats and tool index)
     */
    public static int getCurrentSize() {
        return queue.size();
    }

    /**
     * Offers a traffic document to the queue. Non-blocking.
     *
     * <p>If the queue is full, the oldest document is removed and this one is added; a drop is
     * recorded in {@link ExportStats}. Starts the drain worker on first use. Thread-safe.</p>
     *
     * @param document the document to enqueue; {@code null} is ignored
     */
    public static void offer(Map<String, Object> document) {
        if (document == null) return;
        if (!queue.offer(document)) {
            queue.poll();
            ExportStats.recordTrafficQueueDrop(1);
            queue.offer(document);
        }
        startWorkerIfNeeded();
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
            if (baseUrl == null || baseUrl.isBlank() || !RuntimeConfig.isExportRunning()) {
                try {
                    Map<String, Object> doc = queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    if (doc != null) {
                        queue.offer(doc);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                continue;
            }

            int maxBatch = batchController.getCurrentBatchSize();
            long startNs = System.nanoTime();
            ChunkedBulkSender.Result result = ChunkedBulkSender.push(
                    baseUrl, TRAFFIC_INDEX, queue, maxBatch, BULK_MAX_BYTES, BATCH_MAX_WAIT_MS);
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
            if (queue.size() >= START_DRAIN_BACKLOG_DOCS) {
                return true;
            }
            try {
                long remaining = Math.max(1, deadline - System.currentTimeMillis());
                Map<String, Object> observed = queue.poll(Math.min(STARTUP_POLL_MS, remaining), TimeUnit.MILLISECONDS);
                if (observed != null) {
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
