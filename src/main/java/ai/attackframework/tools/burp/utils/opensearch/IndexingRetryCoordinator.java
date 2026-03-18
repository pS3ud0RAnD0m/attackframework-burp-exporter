package ai.attackframework.tools.burp.utils.opensearch;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

import ai.attackframework.tools.burp.sinks.BulkPayloadEstimator;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

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

    private final RetryQueue queue;
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicBoolean outageMode = new AtomicBoolean(false);
    private volatile long lastOutageLogTime = 0;
    private volatile Thread drainThread;
    private volatile String lastDrainBaseUrl = "";
    private final Object drainThreadLock = new Object();

    public IndexingRetryCoordinator() {
        this.queue = new RetryQueue(MAX_QUEUE_SIZE_PER_INDEX);
    }

    public static IndexingRetryCoordinator getInstance() {
        return Holder.INSTANCE;
    }

    private static final class Holder {
        private static final IndexingRetryCoordinator INSTANCE = new IndexingRetryCoordinator();
    }

    /**
     * Pushes a single document. One attempt only (caller may be on HTTP thread).
     *
     * <p>On failure, offers to the retry queue; if the queue is full, the document is dropped and
     * this method returns {@code false}.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param document the document to index
     * @param indexKey short index key for stats (e.g. {@code "traffic"})
     * @return {@code true} if indexed successfully, {@code false} otherwise
     */
    public boolean pushDocument(String baseUrl, String indexName, Map<String, Object> document, String indexKey) {
        ensureDrainThreadStarted();
        String activeBaseUrl = resolveBaseUrlForOperation(baseUrl);

        if (!outageMode.get()) {
            boolean success = OpenSearchClientWrapper.doPushDocument(activeBaseUrl, indexName, document);
            if (success) {
            consecutiveFailures.set(0);
            if (outageMode.get()) {
                checkRecoveryAndLog(activeBaseUrl);
            }
            return true;
            }
            int fails = consecutiveFailures.incrementAndGet();
            maybeEnterOutageMode(activeBaseUrl, fails);
        }

        boolean offered = queue.offer(indexName, document);
        if (!offered) {
            ExportStats.recordRetryQueueDrop(indexKey, 1);
            Logger.logError("[OpenSearch] Retry queue full for index " + indexName + "; dropping document.");
        }
        return false;
    }

    /**
     * Pushes documents in bulk. Up to 3 attempts with exponential backoff.
     *
     * <p>On partial failure, queues only the failed items. On full failure after retries, queues
     * the whole batch if within queue capacity.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param documents documents to index
     * @param indexKey short index key for stats (e.g. {@code "traffic"})
     * @return number of documents successfully indexed
     */
    public int pushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents, String indexKey) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        ensureDrainThreadStarted();
        String activeBaseUrl = resolveBaseUrlForOperation(baseUrl);

        int successCount = 0;
        List<Map<String, Object>> toQueue = new ArrayList<>();
        boolean inOutage = outageMode.get();
        int maxAttempts = inOutage ? 1 : BULK_RETRY_ATTEMPTS;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            OpenSearchClientWrapper.BulkResult result = OpenSearchClientWrapper.doPushBulkWithDetails(activeBaseUrl, indexName, documents);
            if (result.successCount == documents.size()) {
                consecutiveFailures.set(0);
                BatchSizeController.getInstance().recordSuccess(result.successCount);
                if (outageMode.get()) {
                    checkRecoveryAndLog(activeBaseUrl);
                }
                return result.successCount;
            }
            if (result.successCount > 0) {
                BatchSizeController.getInstance().recordPartialSuccess(result.successCount, documents.size());
                consecutiveFailures.set(0);
                if (outageMode.get()) {
                    checkRecoveryAndLog(activeBaseUrl);
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
                BatchSizeController.getInstance().recordFailure(documents.size());
                toQueue = new ArrayList<>(documents);
                successCount = 0;
                break;
            }
            if (!waitBackoffDelay(attempt)) {
                toQueue = new ArrayList<>(documents);
                successCount = 0;
                break;
            }
        }

        int fails = consecutiveFailures.incrementAndGet();
        maybeEnterOutageMode(activeBaseUrl, fails);

        if (!toQueue.isEmpty()) {
            if (toQueue.size() <= MAX_QUEUE_SIZE_PER_INDEX) {
                int added = queue.offerAll(indexName, toQueue);
                if (added < toQueue.size()) {
                    int dropped = toQueue.size() - added;
                    ExportStats.recordRetryQueueDrop(indexKey, dropped);
                    Logger.logError("[OpenSearch] Retry queue full for index " + indexName + "; dropping " + dropped + " documents.");
                }
            } else {
                ExportStats.recordRetryQueueDrop(indexKey, toQueue.size());
                Logger.logError("[OpenSearch] Bulk failure batch too large to queue (" + toQueue.size() + "); dropping.");
            }
        }
        return successCount;
    }

    private void maybeEnterOutageMode(String baseUrl, int consecutiveFails) {
        if (consecutiveFails != CONSECUTIVE_FAILURES_BEFORE_CHECK) {
            return;
        }
        OpenSearchClientWrapper.OpenSearchStatus status = testConnectionWithRuntimeConfig(baseUrl);
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
        OpenSearchClientWrapper.OpenSearchStatus status = testConnectionWithRuntimeConfig(baseUrl);
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

    private void ensureDrainThreadStarted() {
        if (drainThread != null && drainThread.isAlive()) {
            return;
        }
        synchronized (drainThreadLock) {
            if (drainThread != null && drainThread.isAlive()) {
                return;
            }
            drainThread = new Thread(this::drainLoop, "OpenSearchRetryDrain");
            drainThread.setDaemon(true);
            drainThread.start();
        }
    }

    private void drainLoop() {
        while (true) {
            long interval = outageMode.get() ? DRAIN_INTERVAL_MS_OUTAGE : DRAIN_INTERVAL_MS_NORMAL;
            if (!waitInterval(interval)) {
                break;
            }

            if (outageMode.get() && queue.totalSize() > 0) {
                if (System.currentTimeMillis() - lastOutageLogTime >= OUTAGE_LOG_THROTTLE_MS) {
                    lastOutageLogTime = System.currentTimeMillis();
                    Logger.logError("[OpenSearch] Still unreachable. Queued: " + queue.totalSize() + ". Will retry.");
                }
            }

            String baseUrl = resolveBaseUrlForOperation("");
            if (baseUrl.isBlank()) {
                continue;
            }
            maybeLogDestinationChange(baseUrl);

            for (String indexKey : ExportStats.getIndexKeys()) {
                String indexName = indexNameFromKey(indexKey);
                int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
                List<Map<String, Object>> batch = queue.pollBatch(indexName, batchSize);
                if (batch.isEmpty()) continue;

                int sent = OpenSearchClientWrapper.doPushBulk(baseUrl, indexName, batch);
                if (sent == batch.size()) {
                    BatchSizeController.getInstance().recordSuccess(sent);
                    ExportStats.recordSuccess(indexKey, sent);
                    ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                    if (outageMode.get() && queue.allEmpty()) {
                        checkRecoveryAndLog(baseUrl);
                    }
                } else if (sent > 0) {
                    BatchSizeController.getInstance().recordPartialSuccess(sent, batch.size());
                    ExportStats.recordSuccess(indexKey, sent);
                    ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                    List<Map<String, Object>> reQueue = batch.subList(sent, batch.size());
                    queue.offerAll(indexName, reQueue);
                } else {
                    BatchSizeController.getInstance().recordFailure(batch.size());
                    queue.offerAll(indexName, batch);
                }
            }
        }
    }

    /**
     * Returns the currently effective destination URL for retries.
     *
     * <p>Retry and drain paths should honor live runtime destination changes. This method
     * prefers runtime config and falls back to call-site URL when runtime has not been set.</p>
     */
    static String resolveBaseUrlForOperation(String fallbackBaseUrl) {
        String runtimeBaseUrl = RuntimeConfig.openSearchUrl();
        if (runtimeBaseUrl != null && !runtimeBaseUrl.isBlank()) {
            return runtimeBaseUrl.trim();
        }
        if (fallbackBaseUrl == null) {
            return "";
        }
        return fallbackBaseUrl.trim();
    }

    private static OpenSearchClientWrapper.OpenSearchStatus testConnectionWithRuntimeConfig(String baseUrl) {
        return OpenSearchClientWrapper.testConnection(
                baseUrl,
                RuntimeConfig.openSearchUser(),
                RuntimeConfig.openSearchPassword());
    }

    private void maybeLogDestinationChange(String baseUrl) {
        String previous = lastDrainBaseUrl;
        if (baseUrl.equals(previous)) {
            return;
        }
        lastDrainBaseUrl = baseUrl;
        if (previous != null && !previous.isBlank() && queue.totalSize() > 0) {
            Logger.logInfoPanelOnly("[OpenSearch] Retry drain destination updated while backlog exists: "
                    + previous + " -> " + baseUrl);
        }
    }

    public int getQueueSize(String indexName) {
        return queue.size(indexName);
    }

    private static boolean waitBackoffDelay(int attempt) {
        long delayMs = BACKOFF_BASE_MS * (long) Math.pow(BACKOFF_MULTIPLIER, attempt - 1);
        return waitInterval(delayMs);
    }

    private static boolean waitInterval(long delayMs) {
        if (delayMs <= 0) {
            return !Thread.currentThread().isInterrupted();
        }
        long remainingNanos = TimeUnit.MILLISECONDS.toNanos(delayMs);
        long deadline = System.nanoTime() + remainingNanos;
        while (remainingNanos > 0) {
            LockSupport.parkNanos(remainingNanos);
            if (Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
                return false;
            }
            remainingNanos = deadline - System.nanoTime();
        }
        return true;
    }

    private static long estimateSuccessfulBytes(List<Map<String, Object>> batch, int successCount) {
        if (batch == null || batch.isEmpty() || successCount <= 0) {
            return 0;
        }
        long total = 0;
        for (Map<String, Object> doc : batch) {
            total += BulkPayloadEstimator.estimateBytes(doc);
        }
        return Math.round((double) total * successCount / batch.size());
    }
}
