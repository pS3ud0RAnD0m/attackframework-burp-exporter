package ai.attackframework.tools.burp.sinks;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Forwards extension log events to the {@link IndexNaming#INDEX_PREFIX} (attackframework-tool-burp)
 * index so the Attack Framework can analyze extension/OpenSearch issues centrally.
 *
 * <p>Registers as a {@link Logger.LogListener}; each log event is queued and pushed asynchronously
 * by a single worker thread. Only pushes when export is running and
 * {@link RuntimeConfig#openSearchUrl()} is set.
 * Fire-and-forget; failures are not logged back to avoid feedback loops. If the queue is full,
 * the oldest event is dropped to make room.</p>
 */
public final class ToolIndexLogForwarder implements Logger.LogListener {

    private static final String SCHEMA_VERSION = "1";
    private static final String EVENT_TYPE = "log";
    private static final int QUEUE_CAPACITY = 1000;

    private final BlockingQueue<Map<String, Object>> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "attackframework-tool-log-forwarder");
        t.setDaemon(true);
        return t;
    });

    public ToolIndexLogForwarder() {
        worker.submit(this::drainLoop);
    }

    /**
     * Stops the background drain worker and clears any queued log documents.
     *
     * <p>Safe to call multiple times. Used during extension unload so hot reload does
     * not leave a stale forwarder thread behind.</p>
     */
    public void stop() {
        queue.clear();
        worker.shutdownNow();
    }

    @Override
    public void onLog(String level, String message) {
        if (!RuntimeConfig.isExportReady()) {
            return;
        }
        if (!RuntimeConfig.isOpenSearchExportEnabled()) {
            return;
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("level", level != null ? level : "INFO");
        doc.put("event_type", EVENT_TYPE);
        doc.put("message_text", message != null ? message : "");
        doc.put("source", "burp-exporter");
        doc.put("thread", Thread.currentThread().getName());
        doc.put("extension_version", Version.get());
        doc.put("burp_version", burpVersion());
        doc.put("project_id", projectId());
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        doc.put("document_meta", meta);

        if (!queue.offer(doc)) {
            queue.poll();
            queue.offer(doc);
        }
    }

    private void drainLoop() {
        while (true) {
            try {
                if (!RuntimeConfig.isExportRunning()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }
                if (!RuntimeConfig.isExportReady()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }

                if (!RuntimeConfig.isOpenSearchExportEnabled()) {
                    queue.clear();
                    TimeUnit.SECONDS.sleep(1);
                    continue;
                }

                Map<String, Object> doc = queue.poll(1, TimeUnit.SECONDS);
                if (doc == null) continue;

                String baseUrl = RuntimeConfig.openSearchUrl();
                boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, IndexNaming.indexNameForShortName("tool"), doc);
                if (ok) {
                    ExportStats.recordSuccess("tool", 1);
                } else {
                    ExportStats.recordFailure("tool", 1);
                    ExportStats.recordLastError("tool", "Tool log push failed");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception ignored) {
                // Fire-and-forget; avoid feedback loop
            }
        }
    }

    private static String burpVersion() {
        return BurpRuntimeMetadata.burpVersion();
    }

    private static String projectId() {
        return BurpRuntimeMetadata.projectId();
    }
}
