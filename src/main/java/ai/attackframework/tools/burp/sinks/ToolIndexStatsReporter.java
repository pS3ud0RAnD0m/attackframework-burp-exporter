package ai.attackframework.tools.burp.sinks;

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
 */
public final class ToolIndexStatsReporter {

    private static final int INTERVAL_SECONDS = 30;
    private static final String EVENT_TYPE = "stats_snapshot";

    private static volatile ScheduledExecutorService scheduler;

    private ToolIndexStatsReporter() {}

    /**
     * Starts the periodic stats reporter if not already running.
     *
     * <p>Safe to call from any thread. Uses a single daemon scheduler.</p>
     */
    public static void start() {
        if (scheduler != null) {
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

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("heap_used_bytes", heapUsed);
        message.put("heap_max_bytes", heapMax);
        message.put("traffic_indexed_count", TrafficExportStats.getSuccessCount());
        message.put("traffic_failure_count", TrafficExportStats.getFailureCount());
        message.put("export_running", RuntimeConfig.isExportRunning());

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("timestamp", Instant.now().toString());
        doc.put("level", "INFO");
        doc.put("event_type", EVENT_TYPE);
        doc.put("message", message);
        doc.put("message_text", "stats_snapshot heap_used=" + (heapUsed / (1024 * 1024)) + "MB traffic_indexed=" + TrafficExportStats.getSuccessCount());
        doc.put("extension_version", Version.get());
        return doc;
    }
}
