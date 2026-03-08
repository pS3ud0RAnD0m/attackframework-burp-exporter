package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Bounded queue for traffic documents so the HTTP thread can enqueue and return immediately.
 *
 * <p>A dedicated worker thread drains the queue in batches and pushes via the OpenSearch Bulk API.
 * When full, the oldest document is dropped (backpressure). Batches are limited by count
 * ({@link BatchSizeController}), payload size ({@link BulkPayloadEstimator}, 5 MB cap), and time
 * (flush after 100 ms). Used only by the traffic export path.</p>
 */
public final class TrafficExportQueue {

    private static final String TRAFFIC_INDEX = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final int CAPACITY = 50_000;
    private static final long POLL_TIMEOUT_MS = 50;
    private static final long BATCH_MAX_WAIT_MS = 100;
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final long RAMP_UP_MS = 2_500;

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
        try {
            Thread.sleep(RAMP_UP_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        List<Map<String, Object>> batch = new ArrayList<>(BatchSizeController.getInstance().getCurrentBatchSize());
        while (true) {
            batch.clear();
            long batchStartNanos = System.nanoTime();
            try {
                Map<String, Object> first = queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (first != null) {
                    batch.add(first);
                    long runningBytes = BulkPayloadEstimator.estimateBytes(first);
                    int maxBatch = BatchSizeController.getInstance().getCurrentBatchSize();
                    long maxWaitNanos = BATCH_MAX_WAIT_MS * 1_000_000L;
                    while (batch.size() < maxBatch && runningBytes < BULK_MAX_BYTES) {
                        if ((System.nanoTime() - batchStartNanos) >= maxWaitNanos) {
                            break;
                        }
                        Map<String, Object> doc = queue.poll();
                        if (doc == null) break;
                        long docEst = BulkPayloadEstimator.estimateBytes(doc);
                        if (runningBytes + docEst > BULK_MAX_BYTES && !batch.isEmpty()) {
                            queue.offer(doc);
                            break;
                        }
                        batch.add(doc);
                        runningBytes += docEst;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (batch.isEmpty()) continue;

            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank() || !RuntimeConfig.isExportRunning()) {
                ExportStats.recordFailure("traffic", batch.size());
                continue;
            }

            long startNs = System.nanoTime();
            int success = OpenSearchClientWrapper.pushBulk(baseUrl, TRAFFIC_INDEX, batch);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000;
            ExportStats.recordLastPush("traffic", durationMs);
            ExportStats.recordSuccess("traffic", success);
            if (success < batch.size()) {
                ExportStats.recordFailure("traffic", batch.size() - success);
            }
        }
    }
}
