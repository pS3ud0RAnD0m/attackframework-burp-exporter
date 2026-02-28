package ai.attackframework.tools.burp.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Thread-safe per-index export stats for OpenSearch pushes.
 *
 * <p>Session-scoped: counts and last error/duration are not persisted. Used by
 * StatsPanel and by the tool-index stats snapshot. Index keys align with
 * short names: traffic, tool, settings, sitemap, findings.</p>
 */
public final class ExportStats {

    private static final List<String> INDEX_KEYS = Collections.unmodifiableList(
            Arrays.asList("traffic", "tool", "settings", "sitemap", "findings"));
    private static final int LAST_ERROR_MAX_LEN = 200;

    private static final Map<String, PerIndexStats> STATS = new ConcurrentHashMap<>();

    static {
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
    }

    private ExportStats() {}

    private static PerIndexStats forIndex(String indexKey) {
        PerIndexStats s = STATS.get(indexKey);
        return s != null ? s : STATS.computeIfAbsent(indexKey, k -> new PerIndexStats());
    }

    /** Returns the list of index keys (traffic, tool, settings, sitemap, findings). */
    public static List<String> getIndexKeys() {
        return INDEX_KEYS;
    }

    /** Records successful document push(es) for the given index. */
    public static void recordSuccess(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).successCount.addAndGet(count);
    }

    /** Records failed document push(es) for the given index. */
    public static void recordFailure(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).failureCount.addAndGet(count);
    }

    /** Records the duration in ms of the last push for the given index (-1 if unknown). */
    public static void recordLastPush(String indexKey, long durationMs) {
        forIndex(indexKey).lastPushDurationMs.set(durationMs);
    }

    /** Records the last error for the given index (null or empty clears). */
    public static void recordLastError(String indexKey, String message) {
        if (message == null || message.isEmpty()) {
            forIndex(indexKey).lastError.set(null);
            return;
        }
        String truncated = message.length() <= LAST_ERROR_MAX_LEN
                ? message
                : message.substring(0, LAST_ERROR_MAX_LEN) + "...";
        forIndex(indexKey).lastError.set(truncated);
    }

    public static long getSuccessCount(String indexKey) {
        return forIndex(indexKey).successCount.get();
    }

    public static long getFailureCount(String indexKey) {
        return forIndex(indexKey).failureCount.get();
    }

    /** Returns last push duration in ms, or -1 if not set. */
    public static long getLastPushDurationMs(String indexKey) {
        return forIndex(indexKey).lastPushDurationMs.get();
    }

    public static String getLastError(String indexKey) {
        return forIndex(indexKey).lastError.get();
    }

    /**
     * Returns the number of documents currently queued for retry for the given index
     * (0 when no retry coordinator or queue empty).
     */
    public static int getQueueSize(String indexKey) {
        String indexName = "tool".equals(indexKey)
                ? IndexNaming.INDEX_PREFIX
                : IndexNaming.INDEX_PREFIX + "-" + indexKey;
        return IndexingRetryCoordinator.getInstance().getQueueSize(indexName);
    }

    /** Session total: sum of docs pushed across all indexes. */
    public static long getTotalSuccessCount() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).successCount.get();
        }
        return sum;
    }

    /** Session total: sum of failures across all indexes. */
    public static long getTotalFailureCount() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).failureCount.get();
        }
        return sum;
    }

    private static final class PerIndexStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong lastPushDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
    }
}
