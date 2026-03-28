package ai.attackframework.tools.burp.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe session stats for file-based exports.
 *
 * <p>These counters mirror the high-level OpenSearch export metrics used by {@code StatsPanel},
 * but track only documents and bytes that were actually written to file sinks.</p>
 */
public final class FileExportStats {

    private static final List<String> INDEX_KEYS = Collections.unmodifiableList(
            Arrays.asList("traffic", "tool", "settings", "sitemap", "findings"));
    private static final List<String> TRAFFIC_SOURCE_KEYS = Collections.unmodifiableList(
            Arrays.asList("proxy_live_http", "proxy_history_snapshot", "proxy_websocket"));
    private static final List<String> TRAFFIC_TOOL_TYPE_KEYS = Collections.unmodifiableList(
            Arrays.asList("BURP_AI", "EXTENSIONS", "INTRUDER", "PROXY", "PROXY_HISTORY", "REPEATER", "SCANNER", "SEQUENCER", "UNKNOWN"));
    private static final int LAST_ERROR_MAX_LEN = 200;

    private static final Map<String, PerIndexStats> STATS = new ConcurrentHashMap<>();
    private static final Map<String, TrafficSourceStats> TRAFFIC_SOURCE_STATS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_COUNTS = new ConcurrentHashMap<>();

    static {
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String key : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(key, new TrafficSourceStats());
        }
        for (String key : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_COUNTS.put(key, new AtomicLong(0));
        }
    }

    private FileExportStats() { }

    /** Returns the tracked short index keys used by file-export stats. */
    public static List<String> getIndexKeys() {
        return INDEX_KEYS;
    }

    /** Returns the tracked traffic tool-type keys used by file-export source stats. */
    public static List<String> getTrafficToolTypeKeys() {
        return TRAFFIC_TOOL_TYPE_KEYS;
    }

    /** Records one or more successful file-export document writes for an index key. */
    public static void recordSuccess(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).successCount.addAndGet(count);
    }

    /** Records one or more failed file-export write attempts for an index key. */
    public static void recordFailure(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).failureCount.addAndGet(count);
    }

    /** Records successfully written file-export bytes for an index key. */
    public static void recordExportedBytes(String indexKey, long bytes) {
        if (bytes <= 0) {
            return;
        }
        forIndex(indexKey).successBytes.addAndGet(bytes);
    }

    /** Records the wall-clock duration of the latest successful file write for an index key. */
    public static void recordLastWriteDurationMs(String indexKey, long durationMs) {
        forIndex(indexKey).lastWriteDurationMs.set(durationMs);
    }

    /** Stores the latest file-export error for an index key, truncating overly long messages. */
    public static void recordLastError(String indexKey, String message) {
        if (message == null || message.isBlank()) {
            forIndex(indexKey).lastError.set(null);
            return;
        }
        String truncated = message.length() <= LAST_ERROR_MAX_LEN
                ? message
                : message.substring(0, LAST_ERROR_MAX_LEN) + "...";
        forIndex(indexKey).lastError.set(truncated);
    }

    /** Returns the successful file-export document count for an index key. */
    public static long getSuccessCount(String indexKey) {
        return forIndex(indexKey).successCount.get();
    }

    /** Returns the failed file-export document count for an index key. */
    public static long getFailureCount(String indexKey) {
        return forIndex(indexKey).failureCount.get();
    }

    /** Returns the successful file-export bytes recorded for an index key. */
    public static long getExportedBytes(String indexKey) {
        return forIndex(indexKey).successBytes.get();
    }

    /** Returns the latest successful file-write duration for an index key, or {@code -1}. */
    public static long getLastWriteDurationMs(String indexKey) {
        return forIndex(indexKey).lastWriteDurationMs.get();
    }

    /** Returns the latest file-export error for an index key, or {@code null}. */
    public static String getLastError(String indexKey) {
        return forIndex(indexKey).lastError.get();
    }

    /** Returns the total successful file-export document count across all tracked indexes. */
    public static long getTotalSuccessCount() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getSuccessCount(key);
        }
        return sum;
    }

    /** Returns the total failed file-export document count across all tracked indexes. */
    public static long getTotalFailureCount() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getFailureCount(key);
        }
        return sum;
    }

    /** Returns the total successful file-export bytes across all tracked indexes. */
    public static long getTotalExportedBytes() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getExportedBytes(key);
        }
        return sum;
    }

    /** Records one or more successful traffic document writes for a file-export source key. */
    public static void recordTrafficSourceSuccess(String sourceKey, long count) {
        if (count <= 0) {
            return;
        }
        forTrafficSource(sourceKey).successCount.addAndGet(count);
    }

    /** Records one or more failed traffic document writes for a file-export source key. */
    public static void recordTrafficSourceFailure(String sourceKey, long count) {
        if (count <= 0) {
            return;
        }
        forTrafficSource(sourceKey).failureCount.addAndGet(count);
    }

    /** Returns the successful file-export count for a traffic source key. */
    public static long getTrafficSourceSuccessCount(String sourceKey) {
        return forTrafficSource(sourceKey).successCount.get();
    }

    /** Returns the failed file-export count for a traffic source key. */
    public static long getTrafficSourceFailureCount(String sourceKey) {
        return forTrafficSource(sourceKey).failureCount.get();
    }

    /** Records captured traffic tool-type counts for file-exported traffic documents. */
    public static void recordTrafficToolTypeCaptured(String toolTypeKey, long count) {
        if (count <= 0 || toolTypeKey == null || toolTypeKey.isBlank()) {
            return;
        }
        TRAFFIC_TOOL_TYPE_COUNTS.computeIfAbsent(toolTypeKey, ignored -> new AtomicLong(0)).addAndGet(count);
    }

    /** Returns the captured file-export traffic count for one tool type. */
    public static long getTrafficToolTypeCapturedCount(String toolTypeKey) {
        AtomicLong count = TRAFFIC_TOOL_TYPE_COUNTS.get(toolTypeKey);
        return count == null ? 0L : count.get();
    }

    /** Resets all file-export stats. Intended for tests and process-local lifecycle cleanup. */
    public static void resetForTests() {
        STATS.clear();
        TRAFFIC_SOURCE_STATS.clear();
        TRAFFIC_TOOL_TYPE_COUNTS.clear();
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String key : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(key, new TrafficSourceStats());
        }
        for (String key : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_COUNTS.put(key, new AtomicLong(0));
        }
    }

    private static PerIndexStats forIndex(String indexKey) {
        PerIndexStats stats = STATS.get(indexKey);
        return stats != null ? stats : STATS.computeIfAbsent(indexKey, ignored -> new PerIndexStats());
    }

    private static TrafficSourceStats forTrafficSource(String sourceKey) {
        TrafficSourceStats stats = TRAFFIC_SOURCE_STATS.get(sourceKey);
        return stats != null ? stats : TRAFFIC_SOURCE_STATS.computeIfAbsent(sourceKey, ignored -> new TrafficSourceStats());
    }

    private static final class PerIndexStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong successBytes = new AtomicLong(0);
        final AtomicLong lastWriteDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
    }

    private static final class TrafficSourceStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
    }
}
