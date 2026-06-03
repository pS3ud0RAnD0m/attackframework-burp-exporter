package ai.attackframework.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.SystemMetrics;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Periodically pushes exporter stats snapshots to the Exporter index.
 *
 * <p>Started when export startup reaches the exporter-stats phase; runs on a single daemon
 * scheduler. Snapshots are emitted only while export is running, the {@code exporter} source is
 * enabled, the {@code stats} sub-option is selected, and at least one sink is active. The
 * interval is read from {@link RuntimeConfig#exporterStatsIntervalSeconds()} so UI changes can
 * reschedule the reporter without restarting the extension.</p>
 *
 * <p>Delivery is fire-and-forget: failures are not pushed back into the Exporter index to avoid
 * feedback loops. Set {@link #ENABLED} to {@code false} to disable the reporter for diagnostics or
 * focused testing.</p>
 */
public final class ExporterIndexStatsReporter {

    /** When false, no scheduler is started and no documents are pushed. */
    public static final boolean ENABLED = true;

    private static final String SCHEMA_VERSION = "1";
    private static final String EVENT_TYPE = "stats_snapshot";

    /**
     * Single-owner scheduler for the periodic exporter-stats push.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} on {@link #start()} and torn down
     * by {@link #stop()} during UI stop or extension unload. Recreated on the next
     * {@link #start()} when {@link #refreshScheduleForCurrentState()} detects an interval change.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-exporter-stats");
    private static volatile int scheduledIntervalSeconds = ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS;

    private ExporterIndexStatsReporter() {}

    /**
     * Pushes one stats snapshot immediately.
     *
     * <p>Safe to call from any thread. Returns immediately when export is stopped, the exporter
     * stats sub-option is disabled, or no sink is enabled.</p>
     */
    public static void pushSnapshotNow() {
        if (!ENABLED) return;
        pushSnapshot();
    }

    /**
     * Starts the periodic stats reporter if not already running.
     *
     * <p>Safe to call from any thread. Uses a single daemon scheduler and the current runtime
     * interval from {@link RuntimeConfig#exporterStatsIntervalSeconds()}. Returns immediately when
     * {@link #ENABLED} is {@code false} or exporter stats are disabled.</p>
     */
    public static void start() {
        if (!ENABLED || SCHEDULER.isStarted() || !RuntimeConfig.isExporterStatsEnabled()) {
            return;
        }
        synchronized (ExporterIndexStatsReporter.class) {
            if (SCHEDULER.isStarted() || !RuntimeConfig.isExporterStatsEnabled()) {
                return;
            }
            int intervalSeconds = RuntimeConfig.exporterStatsIntervalSeconds();
            SCHEDULER.getOrStart().scheduleAtFixedRate(
                    ExporterIndexStatsReporter::pushSnapshot,
                    intervalSeconds,
                    intervalSeconds,
                    TimeUnit.SECONDS);
            scheduledIntervalSeconds = intervalSeconds;
        }
    }

    /**
     * Stops the periodic stats scheduler.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
    }

    /**
     * Reconciles the scheduler with the current runtime exporter configuration.
     *
     * <p>Safe to call from any thread. Stops the scheduler when exporter stats are disabled or
     * export is stopped, starts it when newly enabled, and recreates it when the interval changes.</p>
     */
    public static void refreshScheduleForCurrentState() {
        if (!RuntimeConfig.isExportRunning() || !RuntimeConfig.isExporterStatsEnabled()) {
            stop();
            return;
        }
        int currentIntervalSeconds = RuntimeConfig.exporterStatsIntervalSeconds();
        if (!SCHEDULER.isStarted()) {
            start();
            return;
        }
        if (scheduledIntervalSeconds != currentIntervalSeconds) {
            stop();
            start();
        }
    }

    private static void pushSnapshot() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_EXPORTER) || !RuntimeConfig.isExporterStatsEnabled()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
            Map<String, Object> doc = buildSnapshotDoc();
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, RuntimeConfig.indexNameForKey("exporter"), "exporter", doc);
            SingleDocOutcomeRecorder.record("exporter", ok, openSearchActive,
                    "Exporter stats snapshot push failed");
            if (!ok && openSearchActive) {
                Logger.logWarnPanelOnly("[Exporter] Stats snapshot push failed.");
            }
        } catch (Exception e) {
            Logger.logWarnPanelOnly("[Exporter] Stats snapshot push failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
        }
    }

    private static Map<String, Object> buildSnapshotDoc() {
        SystemMetrics.Snapshot sys = SystemMetrics.snapshot();
        long heapUsed = sys.heapUsedBytes();
        long heapMax = sys.heapMaxBytes();
        long nonHeapUsed = sys.nonHeapUsedBytes();
        long nonHeapMax = sys.nonHeapMaxBytes();
        int threadCount = sys.threadCount();
        long gcCount = sys.gcCollectionCount();
        long gcTimeMs = sys.gcCollectionTimeMs();

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("heap_used_bytes", heapUsed);
        if (sys.heapCommittedBytes() >= 0) {
            message.put("heap_committed_bytes", sys.heapCommittedBytes());
        }
        message.put("heap_max_bytes", heapMax);
        if (nonHeapUsed >= 0) {
            message.put("non_heap_used_bytes", nonHeapUsed);
        }
        if (nonHeapMax >= 0) {
            message.put("non_heap_max_bytes", nonHeapMax);
        }
        if (sys.directBufferUsedBytes() >= 0) {
            message.put("direct_buffer_used_bytes", sys.directBufferUsedBytes());
        }
        if (sys.mappedBufferUsedBytes() >= 0) {
            message.put("mapped_buffer_used_bytes", sys.mappedBufferUsedBytes());
        }
        if (threadCount >= 0) {
            message.put("thread_count", threadCount);
        }
        if (sys.peakThreadCount() >= 0) {
            message.put("peak_thread_count", sys.peakThreadCount());
        }
        if (!Double.isNaN(sys.processCpuLoad())) {
            message.put("process_cpu_load", sys.processCpuLoad());
        }
        message.put("traffic_indexed_count", ExportStats.getSuccessCount("traffic"));
        message.put("traffic_failure_count", ExportStats.getFailureCount("traffic"));
        message.put("traffic_indexed_bytes", ExportStats.getExportedBytes("traffic"));
        message.put("traffic_queue_size", ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSize());
        message.put("traffic_queue_drops", ExportStats.getTrafficQueueDrops());
        message.put("traffic_tool_source_fallback_hits", ExportStats.getTrafficToolSourceFallbacks());
        Map<String, Object> repeaterMetadataSources = new LinkedHashMap<>();
        for (String key : ExportStats.getRepeaterMetadataSourceKeys()) {
            repeaterMetadataSources.put(key, ExportStats.getRepeaterMetadataSourceCount(key));
        }
        message.put("repeater_live_metadata_sources", repeaterMetadataSources);
        message.put("repeater_live_metadata_source_summary", ExportStats.describeRepeaterMetadataSourceCounts());
        putTrafficRouteCounts(message);
        message.put("retry_queue_drops_total", ExportStats.getTotalRetryQueueDrops());
        message.put("permanent_drops_total", ExportStats.getTotalPermanentDrops());
        message.put("synthesized_body_params_dropped_total", ExportStats.getSynthesizedBodyParamsDropped());
        message.put("docs_over_params_threshold_total", ExportStats.getDocsOverParamsThreshold());
        message.put("docs_with_skipped_body_enumeration_total", ExportStats.getDocsWithSkippedBodyEnumeration());
        message.put("throughput_docs_per_sec_60", ExportStats.getThroughputDocsPerSecLast60s());
        message.put("total_indexed_bytes", ExportStats.getTotalExportedBytes());
        for (String key : ExportStats.getIndexKeys()) {
            message.put(key + "_indexed_count", ExportStats.getSuccessCount(key));
            message.put(key + "_indexed_bytes", ExportStats.getExportedBytes(key));
        }
        message.put("export_running", RuntimeConfig.isExportRunning());
        message.put("batch_size", ai.attackframework.tools.burp.utils.opensearch.BatchSizeController.getInstance().getCurrentBatchSize());
        message.put("start_to_first_traffic_ms", ExportStats.getStartToFirstTrafficMs());
        ExportStats.ProxyHistorySnapshotStats proxySnapshot = ExportStats.getLastProxyHistorySnapshot();
        if (proxySnapshot != null) {
            message.put("proxy_history_attempted", proxySnapshot.attempted());
            message.put("proxy_history_success", proxySnapshot.success());
            message.put("proxy_history_duration_ms", proxySnapshot.durationMs());
            message.put("proxy_history_docs_per_sec", proxySnapshot.docsPerSecond());
            message.put("proxy_history_final_chunk_target", proxySnapshot.finalChunkTarget());
        }
        long lastPushMs = ExportStats.getLastPushDurationMs("traffic");
        if (lastPushMs >= 0) {
            message.put("last_push_duration_ms", lastPushMs);
        }
        if (gcCount >= 0) {
            message.put("gc_collection_count", gcCount);
        }
        if (gcTimeMs >= 0) {
            message.put("gc_collection_time_ms", gcTimeMs);
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("level", "INFO");
        event.put("source", "burp-exporter");
        event.put("thread", Thread.currentThread().getName());
        event.put("type", EVENT_TYPE);
        event.put("data", message);
        event.put("summary", "stats_snapshot heap_used=" + (heapUsed / (1024 * 1024)) + "MB non_heap_used="
                + (nonHeapUsed >= 0 ? (nonHeapUsed / (1024 * 1024)) + "MB" : "n/a")
                + " threads=" + threadCount
                + " traffic_indexed=" + ExportStats.getSuccessCount("traffic")
                + " repeater_live_sources={" + ExportStats.describeRepeaterMetadataSourceCounts() + "}");
        doc.put("event", event);
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    /**
     * Populates per-route traffic success/failure counters for both sinks on the snapshot.
     *
     * <p>This lets an OpenSearch-only observer see what each sink actually wrote per tool type
     * and per source (for example {@code proxy_history_snapshot}, {@code proxy_websocket})
     * without polling {@code StatsPanel}. Zero-valued entries are retained so downstream
     * dashboards see a stable schema across runs.</p>
     */
    private static void putTrafficRouteCounts(Map<String, Object> message) {
        Map<String, Object> osToolTypeSuccess = new LinkedHashMap<>();
        Map<String, Object> osToolTypeFailure = new LinkedHashMap<>();
        for (String toolType : ExportStats.getTrafficToolTypeKeys()) {
            osToolTypeSuccess.put(toolType, ExportStats.getTrafficToolTypeSuccessCount(toolType));
            osToolTypeFailure.put(toolType, ExportStats.getTrafficToolTypeFailureCount(toolType));
        }
        Map<String, Object> osSourceSuccess = new LinkedHashMap<>();
        Map<String, Object> osSourceFailure = new LinkedHashMap<>();
        for (String source : ExportStats.getTrafficSourceKeys()) {
            osSourceSuccess.put(source, ExportStats.getTrafficSourceSuccessCount(source));
            osSourceFailure.put(source, ExportStats.getTrafficSourceFailureCount(source));
        }
        message.put("traffic_opensearch_tool_type_success", osToolTypeSuccess);
        message.put("traffic_opensearch_tool_type_failure", osToolTypeFailure);
        message.put("traffic_opensearch_source_success", osSourceSuccess);
        message.put("traffic_opensearch_source_failure", osSourceFailure);

        Map<String, Object> fileToolTypeSuccess = new LinkedHashMap<>();
        Map<String, Object> fileToolTypeFailure = new LinkedHashMap<>();
        for (String toolType : ExportStats.getTrafficToolTypeKeys()) {
            fileToolTypeSuccess.put(toolType,
                    ai.attackframework.tools.burp.utils.FileExportStats.getTrafficToolTypeSuccessCount(toolType));
            fileToolTypeFailure.put(toolType,
                    ai.attackframework.tools.burp.utils.FileExportStats.getTrafficToolTypeFailureCount(toolType));
        }
        Map<String, Object> fileSourceSuccess = new LinkedHashMap<>();
        Map<String, Object> fileSourceFailure = new LinkedHashMap<>();
        for (String source : ExportStats.getTrafficSourceKeys()) {
            fileSourceSuccess.put(source,
                    ai.attackframework.tools.burp.utils.FileExportStats.getTrafficSourceSuccessCount(source));
            fileSourceFailure.put(source,
                    ai.attackframework.tools.burp.utils.FileExportStats.getTrafficSourceFailureCount(source));
        }
        message.put("traffic_file_tool_type_success", fileToolTypeSuccess);
        message.put("traffic_file_tool_type_failure", fileToolTypeFailure);
        message.put("traffic_file_source_success", fileSourceSuccess);
        message.put("traffic_file_source_failure", fileSourceFailure);
    }

}
