package ai.attackframework.tools.burp.sinks;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.TrafficExportStats;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Periodically pushes a stats snapshot document to the tool index
 * ({@link IndexNaming#INDEX_PREFIX}) for resource and export metrics in OpenSearch.
 *
 * <p>Started from extension load; runs on a daemon thread. Only pushes when
 * {@link RuntimeConfig#openSearchUrl()} is set. Fire-and-forget; failures are
 * not pushed back to the tool index to avoid feedback loops.</p>
 *
 * <p>Set {@link #ENABLED} to {@code false} to disable the reporter (e.g. to test
 * whether periodic OpenSearch pushes contribute to memory growth).</p>
 */
public final class ToolIndexStatsReporter {

    /** When false, no scheduler is started and no documents are pushed. Set to true to re-enable. */
    public static final boolean ENABLED = false;

    private static final int INTERVAL_SECONDS = 30;
    private static final String EVENT_TYPE = "stats_snapshot";

    private static volatile ScheduledExecutorService scheduler;

    private ToolIndexStatsReporter() {}

    /**
     * Starts the periodic stats reporter if not already running.
     *
     * <p>Safe to call from any thread. Uses a single daemon scheduler.
     * No-op if {@link #ENABLED} is false.</p>
     */
    public static void start() {
        if (!ENABLED || scheduler != null) {
            return;
        }
        synchronized (ToolIndexStatsReporter.class) {
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "attackframework-tool-stats");
                t.setDaemon(true);
                return t;
            });
            exec.scheduleAtFixedRate(
                    ToolIndexStatsReporter::pushSnapshot,
                    INTERVAL_SECONDS,
                    INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
            scheduler = exec;
        }
    }

    private static void pushSnapshot() {
        try {
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            Map<String, Object> doc = buildSnapshotDoc();
            OpenSearchClientWrapper.pushDocument(baseUrl, IndexNaming.INDEX_PREFIX, doc);
        } catch (Exception ignored) {
            // Fire-and-forget; do not log to avoid feedback loop with tool index
        }
    }

    private static Map<String, Object> buildSnapshotDoc() {
        Runtime rt = Runtime.getRuntime();
        long heapUsed = rt.totalMemory() - rt.freeMemory();
        long heapMax = rt.maxMemory();

        long nonHeapUsed = -1;
        long nonHeapMax = -1;
        int threadCount = -1;
        long uptimeMs = -1;
        long gcCount = -1;
        long gcTimeMs = -1;

        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            MemoryUsage nonHeap = memoryBean.getNonHeapMemoryUsage();
            if (nonHeap != null) {
                nonHeapUsed = nonHeap.getUsed() >= 0 ? nonHeap.getUsed() : -1;
                nonHeapMax = nonHeap.getMax() >= 0 ? nonHeap.getMax() : -1;
            }
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            threadCount = threadBean.getThreadCount();
            RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
            uptimeMs = runtimeBean.getUptime();
            gcCount = ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionCount() >= 0 ? gc.getCollectionCount() : 0)
                    .sum();
            gcTimeMs = ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionTime() >= 0 ? gc.getCollectionTime() : 0)
                    .sum();
        } catch (Exception ignored) {
            // JMX may be restricted in some environments
        }

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("heap_used_bytes", heapUsed);
        message.put("heap_max_bytes", heapMax);
        if (nonHeapUsed >= 0) {
            message.put("non_heap_used_bytes", nonHeapUsed);
        }
        if (nonHeapMax >= 0) {
            message.put("non_heap_max_bytes", nonHeapMax);
        }
        if (threadCount >= 0) {
            message.put("thread_count", threadCount);
        }
        if (uptimeMs >= 0) {
            message.put("uptime_ms", uptimeMs);
        }
        message.put("traffic_indexed_count", TrafficExportStats.getSuccessCount());
        message.put("traffic_failure_count", TrafficExportStats.getFailureCount());
        message.put("export_running", RuntimeConfig.isExportRunning());
        long lastPushMs = TrafficExportStats.getLastPushDurationMs();
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
        doc.put("timestamp", Instant.now().toString());
        doc.put("level", "INFO");
        doc.put("event_type", EVENT_TYPE);
        doc.put("message", message);
        doc.put("message_text", "stats_snapshot heap_used=" + (heapUsed / (1024 * 1024)) + "MB non_heap_used=" + (nonHeapUsed >= 0 ? (nonHeapUsed / (1024 * 1024)) + "MB" : "n/a") + " threads=" + threadCount + " traffic_indexed=" + TrafficExportStats.getSuccessCount());
        doc.put("extension_version", Version.get());
        return doc;
    }
}
