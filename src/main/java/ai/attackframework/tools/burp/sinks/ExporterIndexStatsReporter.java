package ai.attackframework.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
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
 *
 * <p>{@code stats_snapshot} {@code event.data} uses a nested layout ({@code jvm}, {@code export},
 * {@code indexes}, {@code traffic}, {@code telemetry}, optional {@code proxy_history_last_run}).
 * Attribution maps include only non-zero counters; file attribution is omitted when file export is
 * off; failure attribution is omitted when traffic has no failures.</p>
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
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("jvm", buildJvmSection(SystemMetrics.snapshot()));
        data.put("export", buildExportSection());
        data.put("indexes", buildIndexesSection());
        data.put("traffic", buildTrafficSection());
        data.put("telemetry", buildTelemetrySection());
        ExportStats.ProxyHistorySnapshotStats proxySnapshot = ExportStats.getLastProxyHistorySnapshot();
        if (proxySnapshot != null) {
            data.put("proxy_history_last_run", buildProxyHistoryLastRunSection(proxySnapshot));
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("level", "INFO");
        event.put("source", "burp-exporter");
        event.put("thread", Thread.currentThread().getName());
        event.put("type", EVENT_TYPE);
        event.put("data", data);
        event.put("summary", EVENT_TYPE);
        doc.put("event", event);
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    private static Map<String, Object> buildJvmSection(SystemMetrics.Snapshot sys) {
        Map<String, Object> jvm = new LinkedHashMap<>();
        jvm.put("heap_used_bytes", sys.heapUsedBytes());
        if (sys.heapCommittedBytes() >= 0) {
            jvm.put("heap_committed_bytes", sys.heapCommittedBytes());
        }
        jvm.put("heap_max_bytes", sys.heapMaxBytes());
        if (sys.nonHeapUsedBytes() >= 0) {
            jvm.put("non_heap_used_bytes", sys.nonHeapUsedBytes());
        }
        if (sys.nonHeapMaxBytes() >= 0) {
            jvm.put("non_heap_max_bytes", sys.nonHeapMaxBytes());
        }
        if (sys.directBufferUsedBytes() >= 0) {
            jvm.put("direct_buffer_used_bytes", sys.directBufferUsedBytes());
        }
        if (sys.mappedBufferUsedBytes() >= 0) {
            jvm.put("mapped_buffer_used_bytes", sys.mappedBufferUsedBytes());
        }
        if (sys.threadCount() >= 0) {
            jvm.put("thread_count", sys.threadCount());
        }
        if (sys.peakThreadCount() >= 0) {
            jvm.put("peak_thread_count", sys.peakThreadCount());
        }
        if (!Double.isNaN(sys.processCpuLoad())) {
            jvm.put("process_cpu_load", sys.processCpuLoad());
        }
        long gcCount = sys.gcCollectionCount();
        if (gcCount >= 0) {
            jvm.put("gc_collection_count", gcCount);
        }
        long gcTimeMs = sys.gcCollectionTimeMs();
        if (gcTimeMs >= 0) {
            jvm.put("gc_collection_time_ms", gcTimeMs);
        }
        return jvm;
    }

    private static Map<String, Object> buildExportSection() {
        Map<String, Object> export = new LinkedHashMap<>();
        export.put("running", RuntimeConfig.isExportRunning());
        export.put("batch_size", ai.attackframework.tools.burp.utils.opensearch.BatchSizeController.getInstance()
                .getCurrentBatchSize());
        export.put("throughput_docs_per_sec_60", ExportStats.getThroughputDocsPerSecLast60s());
        long startToFirstTrafficMs = ExportStats.getStartToFirstTrafficMs();
        if (startToFirstTrafficMs >= 0) {
            export.put("start_to_first_traffic_ms", startToFirstTrafficMs);
        }
        return export;
    }

    private static Map<String, Object> buildIndexesSection() {
        Map<String, Object> indexes = new LinkedHashMap<>();
        for (String key : ExportStats.getIndexKeys()) {
            Map<String, Object> index = new LinkedHashMap<>();
            index.put("count", ExportStats.getSuccessCount(key));
            index.put("bytes", ExportStats.getExportedBytes(key));
            long failures = ExportStats.getFailureCount(key);
            if (failures > 0) {
                index.put("failures", failures);
            }
            indexes.put(key, index);
        }
        return indexes;
    }

    private static Map<String, Object> buildTrafficSection() {
        Map<String, Object> traffic = new LinkedHashMap<>();
        traffic.put("queue_size", TrafficExportQueue.getCurrentSize());
        traffic.put("queue_drops", ExportStats.getTrafficQueueDrops());
        long fallbackHits = ExportStats.getTrafficToolSourceFallbacks();
        if (fallbackHits > 0) {
            traffic.put("tool_source_fallback_hits", fallbackHits);
        }
        long lastPushMs = ExportStats.getLastPushDurationMs("traffic");
        if (lastPushMs >= 0) {
            traffic.put("last_push_duration_ms", lastPushMs);
        }
        Map<String, Object> attribution = buildTrafficAttribution();
        if (!attribution.isEmpty()) {
            traffic.put("attribution", attribution);
        }
        return traffic;
    }

    private static Map<String, Object> buildTrafficAttribution() {
        Map<String, Object> attribution = new LinkedHashMap<>();
        boolean includeFailures = ExportStats.getFailureCount("traffic") > 0;
        if (RuntimeConfig.isOpenSearchActive()) {
            Map<String, Object> openSearch = buildSinkAttribution(
                    ExportStats::getTrafficSourceSuccessCount,
                    ExportStats::getTrafficSourceFailureCount,
                    ExportStats::getTrafficToolTypeSuccessCount,
                    ExportStats::getTrafficToolTypeFailureCount,
                    includeFailures);
            if (!openSearch.isEmpty()) {
                attribution.put("opensearch", openSearch);
            }
        }
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            Map<String, Object> file = buildSinkAttribution(
                    FileExportStats::getTrafficSourceSuccessCount,
                    FileExportStats::getTrafficSourceFailureCount,
                    FileExportStats::getTrafficToolTypeSuccessCount,
                    FileExportStats::getTrafficToolTypeFailureCount,
                    includeFailures);
            if (!file.isEmpty()) {
                attribution.put("file", file);
            }
        }
        return attribution;
    }

    private static Map<String, Object> buildSinkAttribution(
            Function<String, Long> sourceSuccess,
            Function<String, Long> sourceFailure,
            Function<String, Long> toolTypeSuccess,
            Function<String, Long> toolTypeFailure,
            boolean includeFailures) {
        Map<String, Object> sink = new LinkedHashMap<>();
        Map<String, Object> sources = sparseCounts(ExportStats.getTrafficSourceKeys(), sourceSuccess);
        if (!sources.isEmpty()) {
            sink.put("source", sources);
        }
        Map<String, Object> toolTypes = sparseCounts(ExportStats.getTrafficToolTypeKeys(), toolTypeSuccess);
        if (!toolTypes.isEmpty()) {
            sink.put("tool_type", toolTypes);
        }
        if (includeFailures) {
            Map<String, Object> sourceFailures = sparseCounts(ExportStats.getTrafficSourceKeys(), sourceFailure);
            if (!sourceFailures.isEmpty()) {
                sink.put("source_failures", sourceFailures);
            }
            Map<String, Object> toolTypeFailures = sparseCounts(ExportStats.getTrafficToolTypeKeys(), toolTypeFailure);
            if (!toolTypeFailures.isEmpty()) {
                sink.put("tool_type_failures", toolTypeFailures);
            }
        }
        return sink;
    }

    private static Map<String, Object> buildTelemetrySection() {
        Map<String, Object> telemetry = new LinkedHashMap<>();
        long retryDrops = ExportStats.getTotalRetryQueueDrops();
        if (retryDrops > 0) {
            telemetry.put("retry_queue_drops_total", retryDrops);
        }
        long permanentDrops = ExportStats.getTotalPermanentDrops();
        if (permanentDrops > 0) {
            telemetry.put("permanent_drops_total", permanentDrops);
        }
        long synthesizedDropped = ExportStats.getSynthesizedBodyParamsDropped();
        if (synthesizedDropped > 0) {
            telemetry.put("synthesized_body_params_dropped_total", synthesizedDropped);
        }
        long docsOverThreshold = ExportStats.getDocsOverParamsThreshold();
        if (docsOverThreshold > 0) {
            telemetry.put("docs_over_params_threshold_total", docsOverThreshold);
        }
        long skippedBodyEnumeration = ExportStats.getDocsWithSkippedBodyEnumeration();
        if (skippedBodyEnumeration > 0) {
            telemetry.put("docs_with_skipped_body_enumeration_total", skippedBodyEnumeration);
        }
        Map<String, Object> repeaterSources = sparseRepeaterMetadataSources();
        if (!repeaterSources.isEmpty()) {
            telemetry.put("repeater_live_metadata_sources", repeaterSources);
        }
        return telemetry;
    }

    private static Map<String, Object> sparseRepeaterMetadataSources() {
        Map<String, Object> sources = new LinkedHashMap<>();
        for (String key : ExportStats.getRepeaterMetadataSourceKeys()) {
            long count = ExportStats.getRepeaterMetadataSourceCount(key);
            if (count > 0) {
                sources.put(key, count);
            }
        }
        return sources;
    }

    private static Map<String, Object> buildProxyHistoryLastRunSection(ExportStats.ProxyHistorySnapshotStats proxySnapshot) {
        Map<String, Object> run = new LinkedHashMap<>();
        run.put("attempted", proxySnapshot.attempted());
        run.put("success", proxySnapshot.success());
        run.put("duration_ms", proxySnapshot.durationMs());
        run.put("docs_per_sec", proxySnapshot.docsPerSecond());
        run.put("final_chunk_target", proxySnapshot.finalChunkTarget());
        return run;
    }

    private static Map<String, Object> sparseCounts(List<String> keys, Function<String, Long> valueForKey) {
        Map<String, Object> counts = new LinkedHashMap<>();
        for (String key : keys) {
            long value = valueForKey.apply(key);
            if (value > 0) {
                counts.put(key, value);
            }
        }
        return counts;
    }

}
