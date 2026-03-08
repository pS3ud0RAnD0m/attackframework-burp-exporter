package ai.attackframework.tools.burp.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
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
    private static final long THROUGHPUT_WINDOW_MS = 60_000L;
    private static final int THROUGHPUT_CAP = 10_000;

    /** Pairs of { timeMs, count } for successes in the last 60s. Old entries pruned on read. */
    private static final List<long[]> recentSuccesses = Collections.synchronizedList(new ArrayList<>());

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

    /**
     * Records successful document push(es) for the given index.
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param count number of documents; ignored if &lt;= 0
     */
    public static void recordSuccess(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).successCount.addAndGet(count);
        long now = System.currentTimeMillis();
        synchronized (recentSuccesses) {
            recentSuccesses.add(new long[] { now, count });
            if (recentSuccesses.size() > THROUGHPUT_CAP) {
                pruneRecentSuccessesOlderThan(now - THROUGHPUT_WINDOW_MS);
            }
        }
    }

    private static void pruneRecentSuccessesOlderThan(long cutoffMs) {
        Iterator<long[]> it = recentSuccesses.iterator();
        while (it.hasNext()) {
            if (it.next()[0] < cutoffMs) {
                it.remove();
            }
        }
    }

    /**
     * Records failed document push(es) for the given index.
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param count number of failures; ignored if &lt;= 0
     */
    public static void recordFailure(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).failureCount.addAndGet(count);
    }

    /**
     * Records the duration in ms of the last push for the given index.
     *
     * @param indexKey index key
     * @param durationMs duration in milliseconds, or -1 if unknown
     */
    public static void recordLastPush(String indexKey, long durationMs) {
        forIndex(indexKey).lastPushDurationMs.set(durationMs);
    }

    /**
     * Records the last error for the given index.
     *
     * @param indexKey index key
     * @param message error message; {@code null} or empty clears the stored error
     */
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

    /** Returns the session total of documents successfully pushed for the given index. */
    public static long getSuccessCount(String indexKey) {
        return forIndex(indexKey).successCount.get();
    }

    /** Returns the session total of failed push attempts for the given index. */
    public static long getFailureCount(String indexKey) {
        return forIndex(indexKey).failureCount.get();
    }

    /** Returns last push duration in ms, or -1 if not set. */
    public static long getLastPushDurationMs(String indexKey) {
        return forIndex(indexKey).lastPushDurationMs.get();
    }

    /** Returns the last recorded error message for the given index, or {@code null} if none. */
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

    /** Traffic export queue backpressure: count of documents dropped when the queue is full (oldest dropped). */
    private static final AtomicLong trafficQueueDrops = new AtomicLong(0);

    /**
     * Records that one or more documents were dropped from the traffic queue (queue full, drop oldest).
     *
     * @param count number of documents dropped; ignored if &lt;= 0
     */
    public static void recordTrafficQueueDrop(long count) {
        if (count > 0) trafficQueueDrops.addAndGet(count);
    }

    /**
     * Returns the session total of documents dropped from the traffic queue because it was full.
     *
     * @return total drop count (0 or positive)
     */
    public static long getTrafficQueueDrops() {
        return trafficQueueDrops.get();
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

    /** Per-index retry queue: count of documents dropped when the retry queue was full. */
    public static void recordRetryQueueDrop(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).retryQueueDrops.addAndGet(count);
    }

    /** Returns the session total of documents dropped from the retry queue for the given index. */
    public static long getRetryQueueDrops(String indexKey) {
        return forIndex(indexKey).retryQueueDrops.get();
    }

    /** Returns the session total of documents dropped from retry queues across all indexes. */
    public static long getTotalRetryQueueDrops() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).retryQueueDrops.get();
        }
        return sum;
    }

    /**
     * Returns documents per second over the last 60 seconds (rolling throughput).
     * Prunes entries older than the window. Thread-safe.
     *
     * @return docs/sec (0.0 or positive)
     */
    public static double getThroughputDocsPerSecLast60s() {
        long now = System.currentTimeMillis();
        long cutoff = now - THROUGHPUT_WINDOW_MS;
        long sum;
        synchronized (recentSuccesses) {
            pruneRecentSuccessesOlderThan(cutoff);
            sum = 0;
            for (long[] pair : recentSuccesses) {
                if (pair[0] >= cutoff) {
                    sum += pair[1];
                }
            }
        }
        return sum / (THROUGHPUT_WINDOW_MS / 1000.0);
    }

    private static final class PerIndexStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong lastPushDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
        final AtomicLong retryQueueDrops = new AtomicLong(0);
    }
}
