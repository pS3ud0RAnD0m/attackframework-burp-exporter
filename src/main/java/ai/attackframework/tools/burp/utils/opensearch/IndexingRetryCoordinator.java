package ai.attackframework.tools.burp.utils.opensearch;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;

/**
 * Coordinates retries and a bounded per-index queue for OpenSearch indexing.
 * Single-doc: one attempt, then offer to queue on failure (no blocking).
 * Bulk: up to 3 attempts with backoff, then queue failed items. A drain thread
 * periodically sends queued documents.
 */
public final class IndexingRetryCoordinator {

    private static final int MAX_QUEUE_SIZE_PER_INDEX = 10_000;
    private static final int CONSECUTIVE_FAILURES_BEFORE_CHECK = 3;
    private static final int DRAIN_INTERVAL_MS_NORMAL = 5_000;
    private static final int DRAIN_INTERVAL_MS_OUTAGE = 30_000;
    private static final int BULK_RETRY_ATTEMPTS = 3;
    private static final long BACKOFF_BASE_MS = 1_000;
    private static final int BACKOFF_MULTIPLIER = 2;
    private static final int OUTAGE_LOG_THROTTLE_MS = 30_000;
    private static final int DRAIN_BATCH_SIZE = 100;

    private static volatile IndexingRetryCoordinator instance;

    private final RetryQueue queue;
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicBoolean outageMode = new AtomicBoolean(false);
    private volatile long lastOutageLogTime = 0;
    private volatile Thread drainThread;
    private final Object drainThreadLock = new Object();

    public IndexingRetryCoordinator() {
        this.queue = new RetryQueue(MAX_QUEUE_SIZE_PER_INDEX);
    }

    public static IndexingRetryCoordinator getInstance() {
        if (instance == null) {
            synchronized (IndexingRetryCoordinator.class) {
                if (instance == null) {
                    instance = new IndexingRetryCoordinator();
                }
            }
        }
        return instance;
    }

    /**
     * Push a single document. One attempt only (caller may be on HTTP thread).
     * On failure, offers to queue; if queue full, returns false.
     */
    public boolean pushDocument(String baseUrl, String indexName, Map<String, Object> document, String indexKey) {
        ensureDrainThreadStarted(baseUrl);

        if (!outageMode.get()) {
            boolean success = OpenSearchClientWrapper.doPushDocument(baseUrl, indexName, document);
            if (success) {
            consecutiveFailures.set(0);
            if (outageMode.get()) {
                checkRecoveryAndLog(baseUrl);
            }
            return true;
            }
            int fails = consecutiveFailures.incrementAndGet();
            maybeEnterOutageMode(baseUrl, fails);
        }

        boolean offered = queue.offer(indexName, document);
        if (!offered) {
            Logger.logError("[OpenSearch] Retry queue full for index " + indexName + "; dropping document.");
        }
        return false;
    }

    /**
     * Push documents in bulk. Up to 3 attempts with exponential backoff.
     * On partial failure, queues only the failed items. On full failure after retries, queues whole batch (if not too large).
     */
    public int pushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents, String indexKey) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        ensureDrainThreadStarted(baseUrl);

        int successCount = 0;
        List<Map<String, Object>> toQueue = new ArrayList<>();
        boolean inOutage = outageMode.get();
        int maxAttempts = inOutage ? 1 : BULK_RETRY_ATTEMPTS;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            OpenSearchClientWrapper.BulkResult result = OpenSearchClientWrapper.doPushBulkWithDetails(baseUrl, indexName, documents);
            if (result.successCount == documents.size()) {
                consecutiveFailures.set(0);
                if (outageMode.get()) {
                    checkRecoveryAndLog(baseUrl);
                }
                return result.successCount;
            }
            if (result.successCount > 0) {
                consecutiveFailures.set(0);
                if (outageMode.get()) {
                    checkRecoveryAndLog(baseUrl);
                }
                for (int i : result.failedIndices) {
                    if (i >= 0 && i < documents.size()) {
                        toQueue.add(documents.get(i));
                    }
                }
                successCount = result.successCount;
                break;
            }
            if (attempt == maxAttempts) {
                toQueue = new ArrayList<>(documents);
                successCount = 0;
                break;
            }
            try {
                Thread.sleep(BACKOFF_BASE_MS * (long) Math.pow(BACKOFF_MULTIPLIER, attempt - 1));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                toQueue = new ArrayList<>(documents);
                successCount = 0;
                break;
            }
        }

        int fails = consecutiveFailures.incrementAndGet();
        maybeEnterOutageMode(baseUrl, fails);

        if (!toQueue.isEmpty()) {
            if (toQueue.size() <= MAX_QUEUE_SIZE_PER_INDEX) {
                int added = queue.offerAll(indexName, toQueue);
                if (added < toQueue.size()) {
                    Logger.logError("[OpenSearch] Retry queue full for index " + indexName + "; dropping " + (toQueue.size() - added) + " documents.");
                }
            } else {
                Logger.logError("[OpenSearch] Bulk failure batch too large to queue (" + toQueue.size() + "); dropping.");
            }
        }
        return successCount;
    }

    private void maybeEnterOutageMode(String baseUrl, int consecutiveFails) {
        if (consecutiveFails != CONSECUTIVE_FAILURES_BEFORE_CHECK) {
            return;
        }
        OpenSearchClientWrapper.OpenSearchStatus status = OpenSearchClientWrapper.testConnection(baseUrl);
        if (!status.success()) {
            outageMode.set(true);
            logOutageOnce();
        } else {
            consecutiveFailures.set(0);
        }
    }

    private void logOutageOnce() {
        if (System.currentTimeMillis() - lastOutageLogTime < OUTAGE_LOG_THROTTLE_MS) {
            return;
        }
        lastOutageLogTime = System.currentTimeMillis();
        StringBuilder sb = new StringBuilder("[OpenSearch] Unreachable; queuing documents. Queue sizes: ");
        for (String key : ExportStats.getIndexKeys()) {
            String indexName = indexNameFromKey(key);
            int size = queue.size(indexName);
            if (size > 0) {
                sb.append(key).append("=").append(size).append(", ");
            }
        }
        Logger.logError(sb.toString().replaceAll(", $", ""));
    }

    private void checkRecoveryAndLog(String baseUrl) {
        OpenSearchClientWrapper.OpenSearchStatus status = OpenSearchClientWrapper.testConnection(baseUrl);
        if (status.success() && queue.allEmpty()) {
            outageMode.set(false);
            consecutiveFailures.set(0);
            Logger.logError("[OpenSearch] Reachable again; retry queue drained.");
        }
    }

    private static String indexNameFromKey(String indexKey) {
        if ("tool".equals(indexKey)) {
            return IndexNaming.INDEX_PREFIX;
        }
        return IndexNaming.INDEX_PREFIX + "-" + indexKey;
    }

    private void ensureDrainThreadStarted(String baseUrl) {
        if (drainThread != null && drainThread.isAlive()) {
            return;
        }
        synchronized (drainThreadLock) {
            if (drainThread != null && drainThread.isAlive()) {
                return;
            }
            drainThread = new Thread(() -> drainLoop(baseUrl), "OpenSearchRetryDrain");
            drainThread.setDaemon(true);
            drainThread.start();
        }
    }

    private void drainLoop(String baseUrl) {
        while (true) {
            try {
                long interval = outageMode.get() ? DRAIN_INTERVAL_MS_OUTAGE : DRAIN_INTERVAL_MS_NORMAL;
                Thread.sleep(interval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            if (outageMode.get() && queue.totalSize() > 0) {
                if (System.currentTimeMillis() - lastOutageLogTime >= OUTAGE_LOG_THROTTLE_MS) {
                    lastOutageLogTime = System.currentTimeMillis();
                    Logger.logError("[OpenSearch] Still unreachable. Queued: " + queue.totalSize() + ". Will retry.");
                }
            }

            for (String indexKey : ExportStats.getIndexKeys()) {
                String indexName = indexNameFromKey(indexKey);
                List<Map<String, Object>> batch = queue.pollBatch(indexName, DRAIN_BATCH_SIZE);
                if (batch.isEmpty()) continue;

                int sent = OpenSearchClientWrapper.doPushBulk(baseUrl, indexName, batch);
                if (sent == batch.size()) {
                    ExportStats.recordSuccess(indexKey, sent);
                    if (outageMode.get() && queue.allEmpty()) {
                        checkRecoveryAndLog(baseUrl);
                    }
                } else if (sent > 0) {
                    ExportStats.recordSuccess(indexKey, sent);
                    List<Map<String, Object>> reQueue = batch.subList(sent, batch.size());
                    queue.offerAll(indexName, reQueue);
                } else {
                    queue.offerAll(indexName, batch);
                }
            }
        }
    }

    public int getQueueSize(String indexName) {
        return queue.size(indexName);
    }
}
