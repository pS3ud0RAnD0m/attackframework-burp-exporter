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
    private static final List<String> TRAFFIC_SOURCE_KEYS = Collections.unmodifiableList(
            Arrays.asList("proxy_live_http", "proxy_history_snapshot", "proxy_websocket"));
    private static final List<String> TRAFFIC_TOOL_TYPE_KEYS = Collections.unmodifiableList(
            Arrays.asList("BURP_AI", "EXTENSIONS", "INTRUDER", "PROXY", "PROXY_HISTORY", "REPEATER", "SCANNER", "SEQUENCER", "UNKNOWN"));
    private static final int LAST_ERROR_MAX_LEN = 200;
    private static final long THROUGHPUT_WINDOW_MS = 60_000L;
    private static final long THROUGHPUT_WINDOW_SHORT_MS = 10_000L;
    private static final int THROUGHPUT_CAP = 10_000;

    /** Pairs of { timeMs, count } for successes in the last 60s. Old entries pruned on read. */
    private static final List<long[]> recentSuccesses = Collections.synchronizedList(new ArrayList<>());

    private static final Map<String, PerIndexStats> STATS = new ConcurrentHashMap<>();
    private static final Map<String, TrafficSourceStats> TRAFFIC_SOURCE_STATS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_COUNTS = new ConcurrentHashMap<>();
    private static final AtomicLong exportStartRequestedAtMs = new AtomicLong(-1);
    private static final AtomicLong firstTrafficSuccessAtMs = new AtomicLong(-1);
    private static final AtomicReference<ProxyHistorySnapshotStats> lastProxyHistorySnapshot =
            new AtomicReference<>(null);

    static {
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String sourceKey : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(sourceKey, new TrafficSourceStats());
        }
        for (String toolType : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_COUNTS.put(toolType, new AtomicLong(0));
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

    /** Returns known traffic source keys used for source-level traffic stats. */
    public static List<String> getTrafficSourceKeys() {
        return TRAFFIC_SOURCE_KEYS;
    }

    /** Returns known traffic tool type keys shown in Config > Traffic. */
    public static List<String> getTrafficToolTypeKeys() {
        return TRAFFIC_TOOL_TYPE_KEYS;
    }

    private static TrafficSourceStats forTrafficSource(String sourceKey) {
        TrafficSourceStats s = TRAFFIC_SOURCE_STATS.get(sourceKey);
        return s != null ? s : TRAFFIC_SOURCE_STATS.computeIfAbsent(sourceKey, k -> new TrafficSourceStats());
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
        if ("traffic".equals(indexKey)) {
            long startMs = exportStartRequestedAtMs.get();
            if (startMs > 0) {
                firstTrafficSuccessAtMs.compareAndSet(-1, now);
            }
        }
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
     * Records successful traffic pushes for a specific traffic source.
     *
     * @param sourceKey source key (for example {@code "proxy_live_http"})
     * @param count number of successful documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSourceSuccess(String sourceKey, long count) {
        if (count <= 0) return;
        forTrafficSource(sourceKey).successCount.addAndGet(count);
    }

    /**
     * Records failed traffic pushes for a specific traffic source.
     *
     * @param sourceKey source key (for example {@code "proxy_live_http"})
     * @param count number of failed documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSourceFailure(String sourceKey, long count) {
        if (count <= 0) return;
        forTrafficSource(sourceKey).failureCount.addAndGet(count);
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

    /** Returns estimated successful payload bytes pushed for the given index this session. */
    public static long getExportedBytes(String indexKey) {
        return forIndex(indexKey).successBytes.get();
    }

    /**
     * Records estimated successful payload bytes for the given index.
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param bytes estimated successful payload bytes; ignored if {@code <= 0}
     */
    public static void recordExportedBytes(String indexKey, long bytes) {
        if (bytes <= 0) return;
        forIndex(indexKey).successBytes.addAndGet(bytes);
    }

    /** Returns successful traffic pushes for a specific traffic source. */
    public static long getTrafficSourceSuccessCount(String sourceKey) {
        return forTrafficSource(sourceKey).successCount.get();
    }

    /** Returns failed traffic pushes for a specific traffic source. */
    public static long getTrafficSourceFailureCount(String sourceKey) {
        return forTrafficSource(sourceKey).failureCount.get();
    }

    /**
     * Records captured traffic events for a specific traffic tool type.
     *
     * <p>This tracks accepted events at capture time (before queue drain), useful for
     * visibility into tool-source distribution.</p>
     */
    public static void recordTrafficToolTypeCaptured(String toolTypeKey, long count) {
        if (count <= 0) return;
        AtomicLong c = TRAFFIC_TOOL_TYPE_COUNTS.computeIfAbsent(toolTypeKey, k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /** Returns captured traffic event count for a specific tool type. */
    public static long getTrafficToolTypeCapturedCount(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_COUNTS.get(toolTypeKey);
        return c == null ? 0 : c.get();
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
        String indexName = IndexNaming.indexNameForShortName(indexKey);
        return IndexingRetryCoordinator.getInstance().getQueueSize(indexName);
    }

    /** Traffic export queue backpressure: count of documents dropped when the queue is full (oldest dropped). */
    private static final AtomicLong trafficQueueDrops = new AtomicLong(0);
    /** Count of traffic documents persisted to spill storage when memory queue is full. */
    private static final AtomicLong trafficSpillEnqueued = new AtomicLong(0);
    /** Count of traffic documents read back from spill storage into memory queue. */
    private static final AtomicLong trafficSpillDequeued = new AtomicLong(0);
    /** Count of traffic documents dropped because spill storage rejected them. */
    private static final AtomicLong trafficSpillDrops = new AtomicLong(0);
    /** Count of spill documents discovered on startup and available for replay. */
    private static final AtomicLong trafficSpillRecovered = new AtomicLong(0);
    /** Count of spill files pruned by retention policy before replay. */
    private static final AtomicLong trafficSpillExpiredPruned = new AtomicLong(0);
    /** Reason-coded drop counters for extreme traffic handling diagnostics. */
    private static final Map<String, AtomicLong> trafficDropReasons = new ConcurrentHashMap<>();
    /** Count of response-path exports that required request-side tool-type fallback. */
    private static final AtomicLong trafficToolSourceFallbacks = new AtomicLong(0);

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

    /**
     * Records one or more traffic documents persisted to spill storage.
     *
     * @param count number of spilled documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillEnqueued(long count) {
        if (count > 0) {
            trafficSpillEnqueued.addAndGet(count);
        }
    }

    /** Returns total spilled traffic documents persisted this session. */
    public static long getTrafficSpillEnqueued() {
        return trafficSpillEnqueued.get();
    }

    /**
     * Records one or more traffic documents drained from spill storage.
     *
     * @param count number of drained spilled documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillDequeued(long count) {
        if (count > 0) {
            trafficSpillDequeued.addAndGet(count);
        }
    }

    /** Returns total spilled traffic documents drained back into memory this session. */
    public static long getTrafficSpillDequeued() {
        return trafficSpillDequeued.get();
    }

    /**
     * Records one or more traffic documents dropped because spill storage was unavailable/full.
     *
     * @param count number of dropped spill documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillDrop(long count) {
        if (count > 0) {
            trafficSpillDrops.addAndGet(count);
        }
    }

    /** Returns total traffic documents dropped due to spill rejection this session. */
    public static long getTrafficSpillDrops() {
        return trafficSpillDrops.get();
    }

    /**
     * Records one or more spill documents recovered on startup.
     *
     * @param count recovered spill document count; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillRecovered(long count) {
        if (count > 0) {
            trafficSpillRecovered.addAndGet(count);
        }
    }

    /** Returns total spill documents recovered on startup this session. */
    public static long getTrafficSpillRecovered() {
        return trafficSpillRecovered.get();
    }

    /**
     * Records one or more spill files removed by retention cleanup.
     *
     * @param count pruned spill file count; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillExpiredPruned(long count) {
        if (count > 0) {
            trafficSpillExpiredPruned.addAndGet(count);
        }
    }

    /** Returns total spill files pruned by retention this session. */
    public static long getTrafficSpillExpiredPruned() {
        return trafficSpillExpiredPruned.get();
    }

    /**
     * Records a reason-coded traffic drop event.
     *
     * @param reason non-blank reason key
     * @param count number of dropped documents for that reason
     */
    public static void recordTrafficDropReason(String reason, long count) {
        if (reason == null || reason.isBlank() || count <= 0) {
            return;
        }
        trafficDropReasons.computeIfAbsent(reason, k -> new AtomicLong(0)).addAndGet(count);
    }

    /** Returns the total for one reason-coded traffic drop key (0 when absent). */
    public static long getTrafficDropReasonCount(String reason) {
        if (reason == null || reason.isBlank()) {
            return 0;
        }
        AtomicLong counter = trafficDropReasons.get(reason);
        return counter == null ? 0 : counter.get();
    }

    /**
     * Records a response-path export decision that used request-side tool-type fallback.
     *
     * <p>This is used for observability when response tool source is absent but request-side
     * correlation by message id still allows correct traffic export gating.</p>
     */
    public static void recordTrafficToolSourceFallback() {
        trafficToolSourceFallbacks.incrementAndGet();
    }

    /** Returns total response-path tool-source fallbacks recorded this session. */
    public static long getTrafficToolSourceFallbacks() {
        return trafficToolSourceFallbacks.get();
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

    /** Session total: sum of estimated successful payload bytes across all indexes. */
    public static long getTotalExportedBytes() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).successBytes.get();
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
        return getThroughputDocsPerSec(THROUGHPUT_WINDOW_MS);
    }

    /**
     * Returns documents per second over the last 10 seconds (rolling throughput).
     * Prunes entries older than the window. Thread-safe.
     *
     * @return docs/sec (0.0 or positive)
     */
    public static double getThroughputDocsPerSecLast10s() {
        return getThroughputDocsPerSec(THROUGHPUT_WINDOW_SHORT_MS);
    }

    private static double getThroughputDocsPerSec(long windowMs) {
        long now = System.currentTimeMillis();
        long cutoff = now - windowMs;
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
        return sum / (windowMs / 1000.0);
    }

    /**
     * Records that a new export start was requested.
     *
     * <p>Resets startup latency tracking so the next successful traffic push can produce
     * an updated start-to-first-traffic metric.</p>
     */
    public static void recordExportStartRequested() {
        exportStartRequestedAtMs.set(System.currentTimeMillis());
        firstTrafficSuccessAtMs.set(-1);
    }

    /**
     * Returns milliseconds from the latest export Start request to the first successful
     * traffic push, or {@code -1} when not available yet.
     */
    public static long getStartToFirstTrafficMs() {
        long start = exportStartRequestedAtMs.get();
        long first = firstTrafficSuccessAtMs.get();
        if (start <= 0 || first <= 0 || first < start) {
            return -1;
        }
        return first - start;
    }

    /** Returns timestamp (epoch ms) for latest export Start request, or {@code -1}. */
    public static long getExportStartRequestedAtMs() {
        return exportStartRequestedAtMs.get();
    }

    /**
     * Records summary metrics for the latest proxy-history snapshot push.
     *
     * @param attempted attempted document count
     * @param success successful document count
     * @param durationMs wall-clock duration in milliseconds
     * @param finalChunkTarget final chunk target doc count at end of run
     */
    public static void recordProxyHistorySnapshot(
            int attempted, int success, long durationMs, int finalChunkTarget) {
        lastProxyHistorySnapshot.set(new ProxyHistorySnapshotStats(
                attempted,
                success,
                durationMs,
                finalChunkTarget,
                System.currentTimeMillis()));
    }

    /** Returns the latest proxy-history snapshot stats, or {@code null} when none recorded. */
    public static ProxyHistorySnapshotStats getLastProxyHistorySnapshot() {
        return lastProxyHistorySnapshot.get();
    }

    /** Immutable proxy-history snapshot performance summary. */
    public record ProxyHistorySnapshotStats(
            int attempted,
            int success,
            long durationMs,
            int finalChunkTarget,
            long recordedAtMs
    ) {
        /** Returns effective throughput in docs/sec for this snapshot, or 0 when unavailable. */
        public double docsPerSecond() {
            if (durationMs <= 0 || attempted <= 0) {
                return 0.0;
            }
            return attempted / (durationMs / 1000.0);
        }
    }

    private static final class PerIndexStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong successBytes = new AtomicLong(0);
        final AtomicLong lastPushDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
        final AtomicLong retryQueueDrops = new AtomicLong(0);
    }

    private static final class TrafficSourceStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
    }
}
