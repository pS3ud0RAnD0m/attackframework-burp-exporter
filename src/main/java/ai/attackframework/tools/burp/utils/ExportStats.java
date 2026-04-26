package ai.attackframework.tools.burp.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Thread-safe per-index export stats for OpenSearch pushes.
 *
 * <p>Session-scoped: counts and last error/duration are not persisted. Used by
 * StatsPanel and by the Exporter-index stats snapshot. Index keys align with
 * short names: traffic, exporter, settings, sitemap, findings.</p>
 */
public final class ExportStats {

    private static final List<String> INDEX_KEYS = Collections.unmodifiableList(
            Arrays.asList("traffic", "exporter", "settings", "sitemap", "findings"));
    private static final List<String> TRAFFIC_SOURCE_KEYS = Collections.unmodifiableList(
            Arrays.asList("proxy_live_http", "proxy_history_snapshot", "proxy_websocket"));
    private static final List<String> TRAFFIC_TOOL_TYPE_KEYS = Collections.unmodifiableList(
            Arrays.asList(
                    "BURP_AI",
                    "EXTENSIONS",
                    "INTRUDER",
                    "PROXY",
                    "PROXY_HISTORY",
                    "REPEATER",
                    "REPEATER_HISTORY",
                    "SCANNER",
                    "SEQUENCER",
                    "UNKNOWN"));
    private static final List<String> REPEATER_METADATA_SOURCE_KEYS = Collections.unmodifiableList(
            Arrays.asList(
                    "request_identity",
                    "request_hash",
                    "exchange_hash",
                    "ui_fallback",
                    "request_stage_reuse",
                    "ambiguous_null",
                    "none"));
    private static final int LAST_ERROR_MAX_LEN = 200;
    private static final long THROUGHPUT_WINDOW_MS = 60_000L;
    private static final long THROUGHPUT_WINDOW_SHORT_MS = 10_000L;
    private static final int THROUGHPUT_CAP = 10_000;

    /** Pairs of { timeMs, count } for successes in the last 60s. Old entries pruned on read. */
    private static final List<long[]> recentSuccesses = Collections.synchronizedList(new ArrayList<>());

    private static final Map<String, PerIndexStats> STATS = new ConcurrentHashMap<>();
    private static final Map<String, TrafficSourceStats> TRAFFIC_SOURCE_STATS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_FAILURE_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> REPEATER_METADATA_SOURCE_COUNTS = new ConcurrentHashMap<>();
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
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(toolType, new AtomicLong(0));
        }
        for (String metadataSource : REPEATER_METADATA_SOURCE_KEYS) {
            REPEATER_METADATA_SOURCE_COUNTS.put(metadataSource, new AtomicLong(0));
        }
    }

    private ExportStats() {}

    private static PerIndexStats forIndex(String indexKey) {
        PerIndexStats s = STATS.get(indexKey);
        return s != null ? s : STATS.computeIfAbsent(indexKey, k -> new PerIndexStats());
    }

    /** Returns the list of index keys (traffic, exporter, settings, sitemap, findings). */
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

    /** Returns known live-Repeater metadata source keys used in trace and stats summaries. */
    public static List<String> getRepeaterMetadataSourceKeys() {
        return REPEATER_METADATA_SOURCE_KEYS;
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
     * Records successful OpenSearch traffic pushes for a specific tool type.
     */
    public static void recordTrafficToolTypeSuccess(String toolTypeKey, long count) {
        if (count <= 0) return;
        AtomicLong c = TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /** Records failed OpenSearch traffic pushes for a specific tool type. */
    public static void recordTrafficToolTypeFailure(String toolTypeKey, long count) {
        if (count <= 0) return;
        AtomicLong c = TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /** Returns successful OpenSearch traffic push count for a specific tool type. */
    public static long getTrafficToolTypeSuccessCount(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /** Returns failed OpenSearch traffic push count for a specific tool type. */
    public static long getTrafficToolTypeFailureCount(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /**
     * Records one live-Repeater metadata source decision.
     *
     * <p>These counters mirror the trace-level {@code metadataSource} vocabulary so the Stats panel
     * and exporter stats snapshots can summarize which correlation paths are doing the work during a
     * run.</p>
     */
    public static void recordRepeaterMetadataSource(String metadataSource) {
        String normalizedSource = normalizeRepeaterMetadataSource(metadataSource);
        REPEATER_METADATA_SOURCE_COUNTS
                .computeIfAbsent(normalizedSource, ignored -> new AtomicLong(0))
                .incrementAndGet();
    }

    /** Returns the session total for one live-Repeater metadata source label. */
    public static long getRepeaterMetadataSourceCount(String metadataSource) {
        AtomicLong count = REPEATER_METADATA_SOURCE_COUNTS.get(normalizeRepeaterMetadataSource(metadataSource));
        return count == null ? 0 : count.get();
    }

    /** Formats live-Repeater metadata source counters for compact UI and stats summaries. */
    public static String describeRepeaterMetadataSourceCounts() {
        return "id=" + getRepeaterMetadataSourceCount("request_identity")
                + " reqHash=" + getRepeaterMetadataSourceCount("request_hash")
                + " exchHash=" + getRepeaterMetadataSourceCount("exchange_hash")
                + " ui=" + getRepeaterMetadataSourceCount("ui_fallback")
                + " reuse=" + getRepeaterMetadataSourceCount("request_stage_reuse")
                + " ambig=" + getRepeaterMetadataSourceCount("ambiguous_null");
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
        String indexName = RuntimeConfig.indexNameForKey(indexKey);
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
    private static final ReasonCounterSet trafficDropReasons = new ReasonCounterSet();
    /** Count of response-path exports that required request-side tool-type fallback. */
    private static final AtomicLong trafficToolSourceFallbacks = new AtomicLong(0);
    /** Running total of synthesized BODY parameters dropped on binary request bodies. */
    private static final AtomicLong synthesizedBodyParamsDropped = new AtomicLong(0);
    /** Running count of documents whose retained or dropped-synthesized parameter count crossed the WARN threshold. */
    private static final AtomicLong docsOverParamsThreshold = new AtomicLong(0);
    /**
     * Running count of documents that took the heap-safety typed-accessor fast path, where Burp's
     * unfiltered {@code parameters()} call was skipped to avoid materializing synthetic BODY
     * entries from Content-Type-spoofed binary bodies. Tracks how often the E3 protection fired.
     */
    private static final AtomicLong docsWithSkippedBodyEnumeration = new AtomicLong(0);
    /** OpenSearch connection-health: epoch ms of the most recent successful push, or -1 when none yet. */
    private static final AtomicLong openSearchLastSuccessAtMs = new AtomicLong(-1L);
    /** OpenSearch connection-health: consecutive push failures since the last success. */
    private static final AtomicLong openSearchConsecutiveFailures = new AtomicLong(0L);
    /** Reason-coded count of documents silently skipped by scope / tool-source / self-export filters. */
    private static final ReasonCounterSet skipReasonCounts = new ReasonCounterSet();
    /**
     * Live count of bulk requests currently being serialized or awaiting a response.
     *
     * <p>Incremented by every bulk entry point ({@code ChunkedBulkSender} streaming path and the
     * single-shot {@code doPushBulkWithDetails} retry path) and decremented in the matching
     * {@code finally}, so the panel always reads a non-negative live value even when a call
     * throws. Surfaced in the Misc Stats {@code Bulk Requests In-Flight} row.</p>
     */
    private static final AtomicInteger bulkInFlight = new AtomicInteger(0);

    /** Skip reason: document was dropped by the user's Burp scope filter. */
    public static final String SKIP_REASON_SCOPE = "scope";
    /** Skip reason: document originated from a Burp tool source the user did not enable for export. */
    public static final String SKIP_REASON_TOOL_DISABLED = "tool_disabled";
    /** Skip reason: request targets the configured OpenSearch destination (self-export guard). */
    public static final String SKIP_REASON_SELF_OPENSEARCH = "self_opensearch";

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
        trafficDropReasons.record(reason, count);
    }

    /** Returns the total for one reason-coded traffic drop key (0 when absent). */
    public static long getTrafficDropReasonCount(String reason) {
        return trafficDropReasons.get(reason);
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

    /**
     * Records synthesized BODY-typed parameters that were filtered out on binary request bodies.
     *
     * <p>Feeds the {@code Synthesized Body Params Dropped} telemetry counter; ignored when
     * {@code count <= 0}.</p>
     */
    public static void recordSynthesizedBodyParamsDropped(long count) {
        if (count > 0) {
            synthesizedBodyParamsDropped.addAndGet(count);
        }
    }

    /** Returns the session total of synthesized BODY parameters dropped across all exports. */
    public static long getSynthesizedBodyParamsDropped() {
        return synthesizedBodyParamsDropped.get();
    }

    /**
     * Records one document whose retained or dropped-synthesized parameter count tripped
     * the high-cardinality WARN threshold.
     */
    public static void recordDocsOverParamsThreshold() {
        docsOverParamsThreshold.incrementAndGet();
    }

    /** Returns the session total of documents that tripped the parameter-cardinality threshold. */
    public static long getDocsOverParamsThreshold() {
        return docsOverParamsThreshold.get();
    }

    /**
     * Records one document where the typed-accessor fast path was taken to avoid Burp's synthetic
     * BODY enumeration. Bumped exactly once per qualifying document in
     * {@link ai.attackframework.tools.burp.sinks.RequestResponseDocBuilder#collectParameters}.
     */
    public static void recordSkippedBodyParameterEnumeration() {
        docsWithSkippedBodyEnumeration.incrementAndGet();
    }

    /** Returns the session total of documents that took the typed-accessor parameter fast path. */
    public static long getDocsWithSkippedBodyEnumeration() {
        return docsWithSkippedBodyEnumeration.get();
    }

    /**
     * Records a successful OpenSearch push. Updates the connection-health timestamp and resets
     * the consecutive-failure counter so the panel can surface live destination health.
     */
    public static void recordOpenSearchSuccess() {
        openSearchLastSuccessAtMs.set(System.currentTimeMillis());
        openSearchConsecutiveFailures.set(0L);
    }

    /**
     * Records a failed OpenSearch push. Increments the consecutive-failure counter without
     * disturbing the last-success timestamp so the panel shows both values side by side.
     */
    public static void recordOpenSearchFailure() {
        openSearchConsecutiveFailures.incrementAndGet();
    }

    /** Returns the epoch-ms timestamp of the most recent successful OpenSearch push, or -1. */
    public static long getOpenSearchLastSuccessAtMs() {
        return openSearchLastSuccessAtMs.get();
    }

    /** Returns the count of consecutive OpenSearch push failures since the last success. */
    public static long getOpenSearchConsecutiveFailures() {
        return openSearchConsecutiveFailures.get();
    }

    /**
     * Records a silent skip of a document at an exporter filter (scope, tool-source, self-export, etc.).
     *
     * <p>Surfaces in the Misc Stats {@code Skips by Reason} row so the UI can show where
     * coverage gaps come from. Ignores {@code null}, blank, or non-positive counts.</p>
     */
    public static void recordSkipReason(String reason, long count) {
        skipReasonCounts.record(reason, count);
    }

    /** Returns the session total for one skip-reason key (0 when absent). */
    public static long getSkipReasonCount(String reason) {
        return skipReasonCounts.get(reason);
    }

    /**
     * Returns a live copy of the skip-reason counters.
     *
     * <p>Keys are the reason labels ({@code "scope"}, {@code "tool_disabled"},
     * {@code "self_opensearch"}, etc.); values are the counts. The returned map is a snapshot
     * and safe to iterate without synchronization.</p>
     */
    public static Map<String, Long> getSkipReasonCounts() {
        return skipReasonCounts.snapshot();
    }

    /** Returns the session total across all skip reasons. */
    public static long getTotalSkipCount() {
        return skipReasonCounts.total();
    }

    /**
     * Marks the start of a bulk request. Pair with {@link #recordBulkEnd()} in a finally block.
     * Increments the live {@code Bulk Requests In-Flight} counter surfaced on the Misc Stats card.
     *
     * <p>Prefer {@link #openBulk()} in new code so the increment / decrement cannot drift
     * apart on early-return or exceptional paths.</p>
     */
    public static void recordBulkStart() {
        bulkInFlight.incrementAndGet();
    }

    /**
     * Marks the end of a bulk request. Never drops below zero even if callers decrement
     * more than they increment, so misuse cannot produce misleading negative readings.
     */
    public static void recordBulkEnd() {
        bulkInFlight.updateAndGet(v -> v > 0 ? v - 1 : 0);
    }

    /**
     * Opens a {@link BulkInFlightTicket} that increments the in-flight counter immediately and
     * decrements it on {@link AutoCloseable#close()}. Use with try-with-resources:
     *
     * <pre>{@code
     * try (ExportStats.BulkInFlightTicket ignored = ExportStats.openBulk()) {
     *     return executeRequest(...);
     * }
     * }</pre>
     *
     * <p>Equivalent to {@link #recordBulkStart()} + {@link #recordBulkEnd()} in a finally block,
     * but enforces pairing at the type level so an early return or unhandled exception cannot
     * leave the counter elevated.</p>
     */
    public static BulkInFlightTicket openBulk() {
        return new BulkInFlightTicket();
    }

    /** Returns the current count of bulk requests in flight. */
    public static int getBulkInFlight() {
        return bulkInFlight.get();
    }

    /**
     * AutoCloseable handle for the {@code Bulk Requests In-Flight} counter. The constructor
     * increments the counter and {@link #close()} decrements it exactly once, even if called
     * more than once on the same ticket.
     */
    public static final class BulkInFlightTicket implements AutoCloseable {
        private boolean closed;

        private BulkInFlightTicket() {
            recordBulkStart();
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            recordBulkEnd();
        }
    }

    /**
     * Returns the age (ms) of the oldest document currently queued for the given index, or -1
     * when the queue is empty. Surfaces in the Misc Stats {@code Oldest Queued Age} row.
     */
    public static long getOldestQueuedAgeMs(String indexKey) {
        String indexName = RuntimeConfig.indexNameForKey(indexKey);
        long enqueuedAt = IndexingRetryCoordinator.getInstance().getOldestQueuedEnqueuedAtMs(indexName);
        if (enqueuedAt <= 0) {
            return -1;
        }
        long age = System.currentTimeMillis() - enqueuedAt;
        return age < 0 ? 0 : age;
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
     * Per-index permanent-failure drops: count of documents rejected by OpenSearch with a
     * mapping/parse/validation error (classified permanent) and therefore not re-queued for retry.
     *
     * <p>Distinct from {@link #recordRetryQueueDrop(String, long)} which counts capacity-driven
     * drops. The poison-pill path in {@link IndexingRetryCoordinator} short-circuits permanently
     * rejected items and records them here.</p>
     */
    public static void recordPermanentDrop(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).permanentDrops.addAndGet(count);
    }

    /** Returns the session total of permanently dropped documents for the given index. */
    public static long getPermanentDrops(String indexKey) {
        return forIndex(indexKey).permanentDrops.get();
    }

    /** Returns the session total of permanently dropped documents across all indexes. */
    public static long getTotalPermanentDrops() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).permanentDrops.get();
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

    /** Resets process-local export stats. Intended for test teardown only. */
    public static void resetForTests() {
        STATS.clear();
        TRAFFIC_SOURCE_STATS.clear();
        TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.clear();
        TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.clear();
        REPEATER_METADATA_SOURCE_COUNTS.clear();
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String sourceKey : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(sourceKey, new TrafficSourceStats());
        }
        for (String toolType : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(toolType, new AtomicLong(0));
        }
        for (String metadataSource : REPEATER_METADATA_SOURCE_KEYS) {
            REPEATER_METADATA_SOURCE_COUNTS.put(metadataSource, new AtomicLong(0));
        }
        exportStartRequestedAtMs.set(-1);
        firstTrafficSuccessAtMs.set(-1);
        lastProxyHistorySnapshot.set(null);
        synchronized (recentSuccesses) {
            recentSuccesses.clear();
        }
        trafficQueueDrops.set(0);
        trafficSpillEnqueued.set(0);
        trafficSpillDequeued.set(0);
        trafficSpillDrops.set(0);
        trafficSpillRecovered.set(0);
        trafficSpillExpiredPruned.set(0);
        trafficDropReasons.clear();
        trafficToolSourceFallbacks.set(0);
        synthesizedBodyParamsDropped.set(0);
        docsOverParamsThreshold.set(0);
        docsWithSkippedBodyEnumeration.set(0);
        openSearchLastSuccessAtMs.set(-1L);
        openSearchConsecutiveFailures.set(0L);
        skipReasonCounts.clear();
        bulkInFlight.set(0);
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

    private static String normalizeTrafficToolType(String toolTypeKey) {
        return toolTypeKey == null || toolTypeKey.isBlank() ? "UNKNOWN" : toolTypeKey.trim();
    }

    private static final class PerIndexStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong successBytes = new AtomicLong(0);
        final AtomicLong lastPushDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
        final AtomicLong retryQueueDrops = new AtomicLong(0);
        final AtomicLong permanentDrops = new AtomicLong(0);
    }

    private static final class TrafficSourceStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
    }

    private static String normalizeRepeaterMetadataSource(String metadataSource) {
        if (metadataSource == null || metadataSource.isBlank()) {
            return "none";
        }
        String normalized = metadataSource.trim();
        return REPEATER_METADATA_SOURCE_KEYS.contains(normalized) ? normalized : "none";
    }
}
