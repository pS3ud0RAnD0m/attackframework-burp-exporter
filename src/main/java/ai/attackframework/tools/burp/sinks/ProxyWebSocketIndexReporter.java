package ai.attackframework.tools.burp.sinks;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;

/**
 * Pushes Proxy WebSocket history items to the traffic index.
 * Initial snapshot on Start, then every 30s only new messages (by websocket/message id).
 */
public final class ProxyWebSocketIndexReporter {

    private static final String TRAFFIC_INDEX = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final String SCHEMA_VERSION = "1";
    private static final int INTERVAL_SECONDS = 30;
    private static volatile ScheduledExecutorService scheduler;
    private static final Set<String> pushedKeys = ConcurrentHashMap.newKeySet();
    private static volatile boolean runInProgress;

    private ProxyWebSocketIndexReporter() {}

    public static void start() {
        if (scheduler != null) {
            return;
        }
        synchronized (ProxyWebSocketIndexReporter.class) {
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "attackframework-proxy-websocket-reporter");
                t.setDaemon(true);
                return t;
            });
            exec.scheduleAtFixedRate(
                    ProxyWebSocketIndexReporter::pushNewItemsOnly,
                    INTERVAL_SECONDS,
                    INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
            scheduler = exec;
        }
    }

    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning() || !RuntimeConfig.isOpenSearchTrafficEnabled()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            if (!trafficSelectionAllowsWebSockets()) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            if (scheduler != null) {
                scheduler.submit(() -> {
                    try {
                        pushItems(api, baseUrl, true);
                    } catch (Throwable ignored) {
                        // Startup/lifecycle races in Burp can transiently null sub-APIs.
                    }
                });
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Proxy WebSocket index: push failed: " + msg);
        }
    }

    static void pushNewItemsOnly() {
        try {
            if (!RuntimeConfig.isExportRunning() || !RuntimeConfig.isOpenSearchTrafficEnabled()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            if (!trafficSelectionAllowsWebSockets()) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushItems(api, baseUrl, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Proxy WebSocket index: periodic push failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, String baseUrl, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
            if (history == null || history.isEmpty()) {
                return;
            }
            int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
            List<String> batchKeys = new ArrayList<>(batchSize);
            List<Map<String, Object>> batchDocs = new ArrayList<>(batchSize);
            for (ProxyWebSocketMessage msg : history) {
                if (!RuntimeConfig.isExportRunning()) {
                    break;
                }
                String key = messageKey(msg);
                if (!pushAll && pushedKeys.contains(key)) {
                    continue;
                }
                Map<String, Object> doc = buildDocument(api, msg);
                if (doc == null) {
                    continue;
                }
                batchKeys.add(key);
                batchDocs.add(doc);
                if (batchDocs.size() >= BatchSizeController.getInstance().getCurrentBatchSize()) {
                    flushBatch(baseUrl, batchKeys, batchDocs);
                    batchKeys.clear();
                    batchDocs.clear();
                }
            }
            if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
                flushBatch(baseUrl, batchKeys, batchDocs);
            }
        } finally {
            runInProgress = false;
        }
    }

    /** Returns websocket history, tolerating transient Burp lifecycle nulls. */
    private static List<ProxyWebSocketMessage> safeWebSocketHistory(MontoyaApi api) {
        try {
            if (api == null) {
                return List.of();
            }
            var proxy = api.proxy();
            if (proxy == null) {
                return List.of();
            }
            List<ProxyWebSocketMessage> history = proxy.webSocketHistory();
            return history != null ? history : List.of();
        } catch (Throwable ignored) {
            return List.of();
        }
    }

    private static void flushBatch(String baseUrl, List<String> keys, List<Map<String, Object>> docs) {
        int success = OpenSearchClientWrapper.pushBulk(baseUrl, TRAFFIC_INDEX, docs);
        int failure = docs.size() - success;
        ExportStats.recordSuccess("traffic", success);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", success);
        ExportStats.recordFailure("traffic", failure);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", failure);
        if (success == docs.size()) {
            pushedKeys.addAll(keys);
        } else if (failure > 0) {
            ExportStats.recordLastError("traffic", "Proxy WebSocket bulk had " + failure + " failure(s)");
        }
    }

    static Map<String, Object> buildDocument(MontoyaApi api, ProxyWebSocketMessage ws) {
        HttpRequest upgrade = ws.upgradeRequest();
        HttpService service = upgrade == null ? null : upgrade.httpService();

        String url = null;
        try {
            url = upgrade == null ? null : upgrade.url();
        } catch (Exception ignored) {
            // malformed upgrade request
        }
        boolean burpInScope = safeBurpInScope(api, url);
        boolean inScope = ScopeFilter.shouldExport(RuntimeConfig.getState(), url, burpInScope);
        if (!inScope) {
            return null;
        }

        ZonedDateTime t = ws.time();
        String wsTime = t == null ? null : t.toInstant().toString();
        ByteArray payload = ws.payload();
        byte[] payloadBytes = payload == null ? null : payload.getBytes();
        ByteArray edited = ws.editedPayload();
        byte[] editedBytes = edited == null ? null : edited.getBytes();

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("url", url);
        doc.put("host", service == null ? null : service.host());
        doc.put("port", service == null ? null : service.port());
        doc.put("scheme", service == null ? null : (service.secure() ? "https" : "http"));
        doc.put("protocol_transport", service == null ? null : (service.secure() ? "https" : "http"));
        doc.put("protocol_application", "websocket");
        doc.put("protocol_sub", upgrade == null ? null : upgrade.httpVersion());
        doc.put("http_version", upgrade == null ? null : upgrade.httpVersion());
        doc.put("tool", "Proxy WebSocket");
        doc.put("tool_type", "PROXY_WEBSOCKET");
        doc.put("in_scope", inScope);
        doc.put("message_id", ws.id());
        doc.put("path", upgrade == null ? null : upgrade.path());
        doc.put("method", upgrade == null ? null : upgrade.method());
        doc.put("status", null);
        doc.put("mime_type", null);
        doc.put("comment", ws.annotations() != null && ws.annotations().hasNotes() ? ws.annotations().notes() : null);
        doc.put("highlight", ws.annotations() != null && ws.annotations().hasHighlightColor()
                ? (ws.annotations().highlightColor() == null ? null : ws.annotations().highlightColor().name())
                : null);
        doc.put("edited", editedBytes != null);
        doc.put("time_start", wsTime);
        doc.put("time_end", wsTime);
        doc.put("duration_ms", 0);
        doc.put("time_request_sent", wsTime);
        doc.put("response_start_latency_ms", null);
        doc.put("proxy_history_id", null);
        doc.put("listener_port", ws.listenerPort());

        doc.put("request", upgrade == null ? null : RequestResponseDocBuilder.buildRequestDoc(upgrade));
        doc.put("response", null);

        doc.put("websocket_id", ws.webSocketId());
        doc.put("ws_direction", ws.direction() == null ? null : ws.direction().name());
        doc.put("ws_payload", payloadBytes == null ? null : Base64.getEncoder().encodeToString(payloadBytes));
        doc.put("ws_message_type", inferPayloadType(payloadBytes));
        doc.put("ws_payload_text", decodeUtf8OrNull(payloadBytes));
        doc.put("ws_payload_length", payloadBytes == null ? 0 : payloadBytes.length);
        doc.put("ws_edited", editedBytes != null);
        doc.put("ws_edited_payload", editedBytes == null ? null : Base64.getEncoder().encodeToString(editedBytes));
        doc.put("ws_upgrade_request", upgrade == null ? null : RequestResponseDocBuilder.buildRequestDoc(upgrade));
        doc.put("ws_time", wsTime);
        doc.put("ws_message_id", ws.id());

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        doc.put("document_meta", meta);
        return doc;
    }

    private static boolean safeBurpInScope(MontoyaApi api, String url) {
        if (url == null) {
            return false;
        }
        try {
            if (api == null) {
                return false;
            }
            var scope = api.scope();
            return scope != null && scope.isInScope(url);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String messageKey(ProxyWebSocketMessage ws) {
        return ws.webSocketId() + ":" + ws.id();
    }

    private static boolean trafficSelectionAllowsWebSockets() {
        List<String> trafficTypes = RuntimeConfig.getState().trafficToolTypes();
        if (trafficTypes == null) {
            return false;
        }
        return trafficTypes.contains("PROXY") || trafficTypes.contains("PROXY_HISTORY");
    }

    private static String inferPayloadType(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "EMPTY";
        }
        return decodeUtf8OrNull(bytes) != null ? "TEXT" : "BINARY";
    }

    private static String decodeUtf8OrNull(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
