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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
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

    private static final String SCHEMA_VERSION = "1";
    private static final int INTERVAL_SECONDS = 30;

    /**
     * Single-owner scheduler for proxy-WebSocket snapshot and recurring pushes.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} on {@link #start()} and torn down
     * by {@link #stop()} during UI stop or extension unload. A subsequent {@link #start()} or
     * {@link #pushSnapshotNow()} lazily recreates the executor.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-proxy-websocket-reporter");
    private static final Set<String> pushedKeys = ConcurrentHashMap.newKeySet();
    private static volatile boolean runInProgress;

    private ProxyWebSocketIndexReporter() {}

    public static void start() {
        SCHEDULER.startRecurring(
                ProxyWebSocketIndexReporter::pushNewItemsOnly,
                INTERVAL_SECONDS,
                INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Stops the periodic scheduler and clears per-session reporter state.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
        pushedKeys.clear();
        runInProgress = false;
    }

    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning() || !RuntimeConfig.isAnyTrafficExportEnabled()) {
                return;
            }
            if (!trafficSelectionAllowsWebSockets()) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            ScheduledExecutorService exec = SCHEDULER.peek();
            if (exec != null) {
                exec.submit(() -> {
                    try {
                        pushItems(api, true);
                    } catch (Throwable ignored) {
                        // Startup/lifecycle races in Burp can transiently null sub-APIs.
                    }
                });
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[Traffic] Proxy WebSocket snapshot push failed: " + msg);
        }
    }

    static void pushNewItemsOnly() {
        try {
            if (!RuntimeConfig.isExportRunning() || !RuntimeConfig.isAnyTrafficExportEnabled()) {
                return;
            }
            if (!trafficSelectionAllowsWebSockets()) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushItems(api, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[Traffic] Proxy WebSocket periodic push failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, boolean pushAll) {
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
                    flushBatch(batchKeys, batchDocs);
                    batchKeys.clear();
                    batchDocs.clear();
                }
            }
            if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
                flushBatch(batchKeys, batchDocs);
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

    private static void flushBatch(List<String> keys, List<Map<String, Object>> docs) {
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        int attempted = docs.size();
        int success = OpenSearchClientWrapper.pushBulk(
                activeBaseUrl, TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, docs);
        TrafficRouteBucket.recordBulkOutcome(
                TrafficRouteBucket.proxyWebSocket(),
                attempted,
                success,
                openSearchActive,
                "Proxy WebSocket bulk push");
        if (success == attempted) {
            pushedKeys.addAll(keys);
        }
    }

    static Map<String, Object> buildDocument(MontoyaApi api, ProxyWebSocketMessage ws) {
        HttpRequest upgrade = ws.upgradeRequest();
        HttpService service = upgrade == null ? null : upgrade.httpService();

        Map<String, Object> upgradeRequestDoc = upgrade == null
                ? null
                : RequestResponseDocBuilder.buildRequestDoc(upgrade);
        String url = upgrade == null
                ? null
                : RequestResponseDocBuilder.buildBestEffortUrl(upgrade, service, upgradeRequestDoc, "ProxyWebSocket");
        boolean burpInScope = safeBurpInScope(api, url);
        boolean inScope = ScopeFilter.shouldExport(RuntimeConfig.getState(), url, burpInScope);
        if (!inScope) {
            return null;
        }
        Object upgradeHttpVersion = upgradeRequestDoc == null ? null : upgradeRequestDoc.get("http_version");

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
        doc.put("protocol_sub", upgradeHttpVersion);
        doc.put("http_version", upgradeHttpVersion);
        doc.put("tool", "Proxy WebSocket");
        doc.put("tool_type", "PROXY_WEBSOCKET");
        doc.put("burp_in_scope", burpInScope);
        doc.put("message_id", ws.id());
        doc.put("path", upgradeRequestDoc == null ? null : upgradeRequestDoc.get("path"));
        doc.put("method", upgradeRequestDoc == null ? null : upgradeRequestDoc.get("method"));
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

        doc.put("request", upgradeRequestDoc);
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
        return trafficTypes.contains("proxy") || trafficTypes.contains("proxy_history");
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
