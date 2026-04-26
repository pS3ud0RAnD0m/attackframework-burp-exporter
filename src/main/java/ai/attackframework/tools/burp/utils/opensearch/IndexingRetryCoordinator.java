package ai.attackframework.tools.burp.utils.opensearch;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

import ai.attackframework.tools.burp.sinks.ExportReporterLifecycle;
import ai.attackframework.tools.burp.sinks.BulkPayloadEstimator;
import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.concurrent.Workers;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Coordinates OpenSearch retries and bounded fallback queues for failed writes.
 *
 * <p>Single-document writes make one immediate attempt and then offer the document to a retry
 * queue. Bulk writes retry with backoff before queueing only the failed items. A dedicated drain
 * thread periodically retries queued work.</p>
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

    private static final long DRAIN_SHUTDOWN_TIMEOUT_MS = 1_000;

    private final RetryQueue queue;
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private final AtomicBoolean outageMode = new AtomicBoolean(false);
    private volatile long lastOutageLogTime = 0;
    private volatile Thread drainThread;
    private volatile String lastDrainBaseUrl = "";
    private final Object drainThreadLock = new Object();

    /**
     * Creates a coordinator with a fresh bounded retry queue.
     *
     * <p>Production code should normally use {@link #getInstance()}. This constructor remains
     * public so focused tests can create isolated coordinators.</p>
     */
    public IndexingRetryCoordinator() {
        this.queue = new RetryQueue(MAX_QUEUE_SIZE_PER_INDEX);
    }

    /** Returns the shared coordinator used by production export paths. */
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
        if (!RuntimeConfig.isExportReady()) {
            return false;
        }
        if (!RuntimeConfig.isOpenSearchExportEnabled()) {
            return false;
        }
        ensureDrainThreadStarted();
        String activeBaseUrl = resolveBaseUrlForOperation(baseUrl);

        if (!outageMode.get()) {
            boolean success = OpenSearchClientWrapper.doPushDocument(activeBaseUrl, indexName, document);
            if (success) {
                consecutiveFailures.set(0);
                ExportStats.recordOpenSearchSuccess();
                if (outageMode.get()) {
                    checkRecoveryAndLog(activeBaseUrl);
                }
                return true;
            }
            ExportStats.recordOpenSearchFailure();
            int fails = consecutiveFailures.incrementAndGet();
            if (maybeEnterOutageMode(activeBaseUrl, fails)) {
                return false;
            }
        }

        if (!RuntimeConfig.isExportReady()) {
            return false;
        }

        boolean offered = queue.offer(indexName, document);
        if (!offered) {
            ExportStats.recordRetryQueueDrop(indexKey, 1);
            Logger.logErrorPanelOnly("[OpenSearch] Retry queue full for index " + indexName + "; dropping document.");
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
        if (!RuntimeConfig.isExportReady()) {
            return 0;
        }
        if (!RuntimeConfig.isOpenSearchExportEnabled()) {
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
                ExportStats.recordOpenSearchSuccess();
                BatchSizeController.getInstance().recordSuccess(result.successCount);
                if (outageMode.get()) {
                    checkRecoveryAndLog(activeBaseUrl);
                }
                return result.successCount;
            }
            if (result.successCount > 0) {
                BatchSizeController.getInstance().recordPartialSuccess(result.successCount, documents.size());
                consecutiveFailures.set(0);
                ExportStats.recordOpenSearchSuccess();
                if (outageMode.get()) {
                    checkRecoveryAndLog(activeBaseUrl);
                }
                toQueue = filterTransientFailures(documents, result.failedItems, indexName, indexKey);
                successCount = result.successCount;
                break;
            }
            if (attempt == maxAttempts) {
                BatchSizeController.getInstance().recordFailure(documents.size());
                ExportStats.recordOpenSearchFailure();
                toQueue = filterTransientFailures(documents, result.failedItems, indexName, indexKey);
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
        if (maybeEnterOutageMode(activeBaseUrl, fails)) {
            return successCount;
        }

        if (!RuntimeConfig.isExportReady()) {
            return successCount;
        }

        if (!toQueue.isEmpty()) {
            if (toQueue.size() <= MAX_QUEUE_SIZE_PER_INDEX) {
                int added = queue.offerAll(indexName, toQueue);
                if (added < toQueue.size()) {
                    int dropped = toQueue.size() - added;
                    ExportStats.recordRetryQueueDrop(indexKey, dropped);
                    Logger.logErrorPanelOnly("[OpenSearch] Retry queue full for index " + indexName + "; dropping " + dropped + " documents.");
                }
            } else {
                ExportStats.recordRetryQueueDrop(indexKey, toQueue.size());
                Logger.logErrorPanelOnly("[OpenSearch] Bulk failure batch too large to queue (" + toQueue.size() + "); dropping.");
            }
        }
        return successCount;
    }

    /**
     * Clears queued retry state and resets outage/failure tracking without touching successful stats.
     *
     * <p>Used when export is intentionally stopped or a Start attempt fails, so queued retries do
     * not continue behind a stopped UI.</p>
     */
    public void clearPendingWork() {
        queue.clearAll();
        consecutiveFailures.set(0);
        outageMode.set(false);
        lastOutageLogTime = 0;
        lastDrainBaseUrl = "";
    }

    /**
     * Exposes drain-thread liveness for lifecycle and unload-termination tests.
     *
     * @return {@code true} when the drain thread reference is non-null and still alive
     */
    public boolean isDrainThreadAlive() {
        Thread worker = drainThread;
        return worker != null && worker.isAlive();
    }

    /**
     * Interrupts and joins the drain thread so the extension unloads cleanly.
     *
     * <p>Safe to call from any thread and safe to call more than once. The drain thread is
     * recreated lazily by {@link #ensureDrainThreadStarted()} on the next push. Delegates
     * termination to {@link Workers} so shutdown semantics match every other extension-owned
     * worker; if the thread does not exit within {@link #DRAIN_SHUTDOWN_TIMEOUT_MS} milliseconds,
     * the current thread's interrupt flag is restored and the method returns.</p>
     */
    public void stopDrainThread() {
        Thread worker;
        synchronized (drainThreadLock) {
            worker = drainThread;
            drainThread = null;
        }
        Workers.awaitThreadJoin(worker, DRAIN_SHUTDOWN_TIMEOUT_MS);
    }

    private boolean maybeEnterOutageMode(String baseUrl, int consecutiveFails) {
        if (consecutiveFails != CONSECUTIVE_FAILURES_BEFORE_CHECK) {
            return false;
        }
        Logger.logWarnPanelOnly("[OpenSearch] Repeated push failures detected; testing destination health.");
        OpenSearchClientWrapper.OpenSearchStatus status = testConnectionWithRuntimeConfig(baseUrl);
        if (!status.success()) {
            outageMode.set(true);
            logOutageOnce();
            return handlePersistentDestinationFailure(status);
        } else {
            consecutiveFailures.set(0);
        }
        return false;
    }

    private boolean handlePersistentDestinationFailure(OpenSearchClientWrapper.OpenSearchStatus status) {
        if (!RuntimeConfig.disableOpenSearchDestination()) {
            return false;
        }
        clearPendingWork();
        String failureKind = "Failed".equals(status.authenticationStatus())
                ? "authentication failures"
                : "connectivity failures";
        String detail = status.message() == null || status.message().isBlank()
                ? failureKind
                : failureKind + " (" + status.message() + ")";
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            String message = "OpenSearch export disabled after repeated " + detail + ". Files export will continue.";
            Logger.logErrorPanelOnly("[OpenSearch] " + message);
            ControlStatusBridge.post(message);
            return true;
        }
        String message = "OpenSearch export disabled after repeated " + detail + ". No destinations remain; export stopped.";
        Logger.logErrorPanelOnly("[OpenSearch] " + message);
        ControlStatusBridge.post(message);
        ExportReporterLifecycle.stopAndClearPendingExportWork();
        return true;
    }

    private void logOutageOnce() {
        if (queue.totalSize() == 0) {
            return;
        }
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
        Logger.logWarnPanelOnly(sb.toString().replaceAll(", $", ""));
    }

    private void checkRecoveryAndLog(String baseUrl) {
        OpenSearchClientWrapper.OpenSearchStatus status = testConnectionWithRuntimeConfig(baseUrl);
        if (status.success() && queue.allEmpty()) {
            outageMode.set(false);
            consecutiveFailures.set(0);
            Logger.logInfoPanelOnly("[OpenSearch] Reachable again; retry queue drained.");
        }
    }

    private static String indexNameFromKey(String indexKey) {
        return RuntimeConfig.indexNameForKey(indexKey);
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

            if (!RuntimeConfig.isExportReady()) {
                continue;
            }

            if (outageMode.get() && queue.totalSize() > 0) {
                if (System.currentTimeMillis() - lastOutageLogTime >= OUTAGE_LOG_THROTTLE_MS) {
                    lastOutageLogTime = System.currentTimeMillis();
                    Logger.logWarnPanelOnly("[OpenSearch] Still unreachable. Queued: "
                            + queue.totalSize() + ". Will retry.");
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

                OpenSearchClientWrapper.BulkResult result =
                        OpenSearchClientWrapper.doPushBulkWithDetails(baseUrl, indexName, batch);
                int sent = result.successCount;
                if (sent == batch.size()) {
                    BatchSizeController.getInstance().recordSuccess(sent);
                    ExportStats.recordSuccess(indexKey, sent);
                    ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                    ExportStats.recordOpenSearchSuccess();
                    if (outageMode.get() && queue.allEmpty()) {
                        checkRecoveryAndLog(baseUrl);
                    }
                } else if (sent > 0) {
                    BatchSizeController.getInstance().recordPartialSuccess(sent, batch.size());
                    ExportStats.recordSuccess(indexKey, sent);
                    ExportStats.recordExportedBytes(indexKey, estimateSuccessfulBytes(batch, sent));
                    ExportStats.recordOpenSearchSuccess();
                    List<Map<String, Object>> reQueue = filterTransientFailures(batch, result.failedItems, indexName, indexKey);
                    queue.offerAll(indexName, reQueue);
                } else {
                    BatchSizeController.getInstance().recordFailure(batch.size());
                    ExportStats.recordOpenSearchFailure();
                    List<Map<String, Object>> reQueue = filterTransientFailures(batch, result.failedItems, indexName, indexKey);
                    queue.offerAll(indexName, reQueue);
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

    /**
     * Returns the enqueue timestamp (epoch ms) of the oldest queued document for the given index,
     * or {@code -1} when the queue is empty. Used by {@link ExportStats#getOldestQueuedAgeMs(String)}
     * to surface the {@code Oldest Queued Age} row on the Misc Stats panel.
     */
    public long getOldestQueuedEnqueuedAtMs(String indexName) {
        return queue.oldestEnqueuedAtMs(indexName);
    }

    /**
     * Returns the approximate total bytes of documents currently queued for retry on the given
     * index. Delegates to {@link RetryQueue#bytesEstimate(String)}; intended for low-frequency
     * observability callers (StatsPanel).
     */
    public long getQueueBytesEstimate(String indexName) {
        return queue.bytesEstimate(indexName);
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

    /**
     * Partitions failed bulk items into transient (re-queued) and permanent (dropped) sets.
     *
     * <p>Transient failures (cluster backpressure, 429s, timeouts, unknown types) are returned as
     * the re-queue list so the drain thread tries them again. Permanent failures (mapping and
     * parse errors - see {@link BulkErrorClassification}) are counted via
     * {@link ExportStats#recordPermanentDrop(String, long)}, counted in the per-index failure
     * total, and otherwise discarded.</p>
     *
     * <p>When no per-item detail is available (e.g. network error before OpenSearch responded)
     * the whole batch is treated as transient so the drain can retry on a later pass.</p>
     */
    /** Package-private for direct testing of the poison-pill branch. */
    static List<Map<String, Object>> filterTransientFailures(
            List<Map<String, Object>> batch,
            List<OpenSearchClientWrapper.FailedItem> failedItems,
            String indexName,
            String indexKey) {
        if (batch == null || batch.isEmpty()) {
            return new ArrayList<>();
        }
        if (failedItems == null || failedItems.isEmpty()) {
            return new ArrayList<>(batch);
        }
        List<Map<String, Object>> toRetry = new ArrayList<>();
        int permanentCount = 0;
        for (OpenSearchClientWrapper.FailedItem item : failedItems) {
            int idx = item.index();
            if (idx < 0 || idx >= batch.size()) {
                continue;
            }
            if (BulkErrorClassification.of(item.type()) == BulkErrorClassification.PERMANENT) {
                permanentCount++;
            } else {
                toRetry.add(batch.get(idx));
            }
        }
        if (permanentCount > 0) {
            ExportStats.recordPermanentDrop(indexKey, permanentCount);
            Logger.logErrorPanelOnly("[OpenSearch] Dropped " + permanentCount
                    + " permanently rejected document(s) from retry for index " + indexName + ".");
        }
        return toRetry;
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
