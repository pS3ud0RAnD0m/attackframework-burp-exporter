package ai.attackframework.tools.burp.sinks;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Pushes the current runtime configuration as a document to the tool index
 * when export is started or when the user saves config while export is running.
 */
public final class ToolIndexConfigReporter {

    private static final String SCHEMA_VERSION = "1";
    private static final String EVENT_TYPE = "config_snapshot";
    private static final String SOURCE = "burp-exporter";

    private ToolIndexConfigReporter() {}

    /**
     * Pushes one config snapshot to the tool index if export is running and
     * OpenSearch URL is set. Safe to call from any thread. Fire-and-forget.
     */
    public static void pushConfigSnapshot() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            Map<String, Object> doc = buildConfigDoc(RuntimeConfig.getState());
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, IndexNaming.INDEX_PREFIX, doc);
            if (ok) {
                ExportStats.recordSuccess("tool", 1);
            } else {
                ExportStats.recordFailure("tool", 1);
                ExportStats.recordLastError("tool", "Tool config snapshot push failed");
            }
        } catch (Exception ignored) {
            // Fire-and-forget; avoid feedback loop with tool index
        }
    }

    private static Map<String, Object> buildConfigDoc(ConfigState.State state) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("data_sources", state.dataSources() != null ? new ArrayList<>(state.dataSources()) : List.of());
        message.put("scope_type", state.scopeType());
        List<Map<String, Object>> custom = new ArrayList<>();
        if (state.customEntries() != null) {
            for (ConfigState.ScopeEntry e : state.customEntries()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("value", e.value());
                entry.put("kind", e.kind().name());
                custom.add(entry);
            }
        }
        message.put("custom_entries", custom);
        ConfigState.Sinks sinks = state.sinks();
        if (sinks != null) {
            Map<String, Object> sinksMap = new LinkedHashMap<>();
            sinksMap.put("files_enabled", sinks.filesEnabled());
            sinksMap.put("files_path", sinks.filesPath() != null ? sinks.filesPath() : "");
            sinksMap.put("os_enabled", sinks.osEnabled());
            sinksMap.put("open_search_url", sinks.openSearchUrl() != null ? sinks.openSearchUrl() : "");
            message.put("sinks", sinksMap);
        }

        String messageText = "config_snapshot scope=" + state.scopeType()
                + " sources=" + (state.dataSources() != null ? state.dataSources().size() : 0);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("level", "INFO");
        doc.put("event_type", EVENT_TYPE);
        doc.put("source", SOURCE);
        doc.put("message", message);
        doc.put("message_text", messageText);
        doc.put("extension_version", Version.get());
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        doc.put("document_meta", meta);
        return doc;
    }
}
