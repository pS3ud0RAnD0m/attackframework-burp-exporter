package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Bounded queue for traffic documents so the HTTP thread can enqueue and return immediately.
 * A dedicated worker thread drains the queue in batches and pushes via OpenSearch Bulk API.
 * When full, the oldest document is dropped (backpressure). Used only by the traffic export path.
 */
public final class TrafficExportQueue {

    private static final String TRAFFIC_INDEX = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final int CAPACITY = 50_000;
    private static final long POLL_TIMEOUT_MS = 50;

    private static final LinkedBlockingQueue<Map<String, Object>> queue = new LinkedBlockingQueue<>(CAPACITY);
    private static final AtomicBoolean workerStarted = new AtomicBoolean(false);

    private TrafficExportQueue() {}

    /**
     * Offers a traffic document to the queue. Non-blocking. If the queue is full, the oldest
     * document is removed and this one is added. Starts the drain worker on first use.
     */
    public static void offer(Map<String, Object> document) {
        if (document == null) return;
        if (!queue.offer(document)) {
            queue.poll();
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
        List<Map<String, Object>> batch = new ArrayList<>(BatchSizeController.getInstance().getCurrentBatchSize());
        while (true) {
            batch.clear();
            try {
                Map<String, Object> first = queue.poll(POLL_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (first != null) {
                    batch.add(first);
                    int maxBatch = BatchSizeController.getInstance().getCurrentBatchSize();
                    while (batch.size() < maxBatch) {
                        Map<String, Object> doc = queue.poll();
                        if (doc == null) break;
                        batch.add(doc);
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
