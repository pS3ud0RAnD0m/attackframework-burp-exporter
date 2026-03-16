package ai.attackframework.tools.burp.sinks;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Burp HTTP handler that indexes request/response traffic into the OpenSearch traffic index.
 *
 * <p>Builds the document on Burp's HTTP thread and enqueues it to {@link TrafficExportQueue};
 * a dedicated worker drains the queue in batches and pushes via the Bulk API. The HTTP thread
 * is not blocked on network I/O. Only indexes when OpenSearch traffic export is enabled, the
 * OpenSearch URL is set, and the request passes scope filtering. Document shape matches
 * {@code /opensearch/mappings/traffic.json}.</p>
 */
public final class OpenSearchTrafficHandler implements HttpHandler {

    private static final String INDEX_NAME = IndexNaming.INDEX_PREFIX + "-traffic";
    private static final String SCHEMA_VERSION = "1";

    /** Delay after which a request with no response is exported as an orphan (Chromium-aligned). */
    private static final long ORPHAN_TIMEOUT_MS = 120_000L;
    private static final int ORPHAN_CHECK_INTERVAL_SECONDS = 30;
    /** Sentinel for response when no response was received (e.g. timeout). */
    private static final int ORPHAN_STATUS = 0;
    private static final String ORPHAN_REASON_PHRASE = "Timeout";

    private static final ConcurrentHashMap<Integer, PendingOrphan> pendingOrphans = new ConcurrentHashMap<>();

    static {
        ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "attackframework-orphan-export");
            t.setDaemon(true);
            return t;
        });
        exec.scheduleAtFixedRate(
                OpenSearchTrafficHandler::flushOrphanedRequests,
                ORPHAN_CHECK_INTERVAL_SECONDS,
                ORPHAN_CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /** Whether traffic from this tool source should be exported (user-selected tool types only). */
    private static boolean shouldExportTrafficByToolSource(ToolType toolType) {
        if (toolType == null) {
            return false;
        }
        var types = RuntimeConfig.getState().trafficToolTypes();
        return types != null && types.contains(toolType.name());
    }

    /**
     * Whether null/unknown tool-source traffic should be exported.
     *
     * <p>Some Burp flows do not provide tool source on response/request callbacks. We allow these
     * events when Proxy export is enabled so normal browser-driven Proxy traffic is not dropped.</p>
     */
    private static boolean shouldExportNullToolSourceTraffic() {
        var types = RuntimeConfig.getState().trafficToolTypes();
        return types != null && types.contains("PROXY");
    }

    /**
     * True if the request is to the configured OpenSearch base URL (same host and port).
     * Used when tool type is EXTENSIONS to exclude this extension's own export traffic.
     */
    private static boolean isRequestToConfiguredOpenSearch(String requestHost, int requestPort) {
        String baseUrl = RuntimeConfig.openSearchUrl();
        if (baseUrl == null || baseUrl.isBlank() || requestHost == null || requestHost.isEmpty()) {
            return false;
        }
        try {
            URI uri = URI.create(baseUrl.trim());
            String configHost = uri.getHost();
            if (configHost == null) {
                return false;
            }
            int configPort = uri.getPort();
            if (configPort < 0) {
                configPort = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            return configHost.equalsIgnoreCase(requestHost) && configPort == requestPort;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isOpenSearchTrafficEnabled()
                || RuntimeConfig.openSearchUrl().isBlank()) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope())) {
            return RequestToBeSentAction.continueWith(request);
        }
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        if (!shouldExportTrafficByToolSource(toolType)) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (toolType == ToolType.EXTENSIONS) {
            HttpService svc = request.httpService();
            if (svc != null && isRequestToConfiguredOpenSearch(svc.host(), svc.port())) {
                return RequestToBeSentAction.continueWith(request);
            }
        }
        long requestSentMs = System.currentTimeMillis();
        ToolSource reqToolSource = request.toolSource();
        ToolType reqToolType = reqToolSource == null ? null : reqToolSource.toolType();
        Map<String, Object> skeleton = buildOrphanDocumentSkeleton(request, requestSentMs);
        if (skeleton != null) {
            pendingOrphans.put(request.messageId(), new PendingOrphan(skeleton, requestSentMs, reqToolType));
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!RuntimeConfig.isExportRunning()) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (!RuntimeConfig.isOpenSearchTrafficEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }

        String baseUrl = RuntimeConfig.openSearchUrl();
        if (baseUrl.isBlank()) {
            return ResponseReceivedAction.continueWith(response);
        }

        HttpRequest request = response.initiatingRequest();
        if (request == null) {
            return ResponseReceivedAction.continueWith(response);
        }

        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope());
        if (!inScope) {
            return ResponseReceivedAction.continueWith(response);
        }

        PendingOrphan pending = pendingOrphans.get(response.messageId());
        ToolType requestFallbackType = pending == null ? null : pending.toolType;
        ToolSource responseSource = response.toolSource();
        ToolType responseType = responseSource == null ? null : responseSource.toolType();
        if (responseType == null) {
            ExportStats.recordTrafficToolSourceFallback();
        }
        // Prefer selected response source, then selected request-correlated source.
        ToolType toolType = null;
        if (shouldExportTrafficByToolSource(responseType)) {
            toolType = responseType;
        } else if (shouldExportTrafficByToolSource(requestFallbackType)) {
            toolType = requestFallbackType;
        } else if (responseType == null && requestFallbackType == null && shouldExportNullToolSourceTraffic()) {
            toolType = null; // allowed unknown source when proxy traffic export is enabled
        } else {
            pendingOrphans.remove(response.messageId());
            return ResponseReceivedAction.continueWith(response);
        }

        if (toolType == ToolType.EXTENSIONS || toolType == null) {
            HttpService svc = request.httpService();
            if (svc != null && isRequestToConfiguredOpenSearch(svc.host(), svc.port())) {
                pendingOrphans.remove(response.messageId());
                return ResponseReceivedAction.continueWith(response);
            }
        }

        long responseReceivedMs = System.currentTimeMillis();
        Long requestSentMs = pending == null ? null : pending.timestamp;

        Map<String, Object> document = buildDocument(response, request, inScope, requestSentMs, responseReceivedMs, toolType);
        ExportStats.recordTrafficToolTypeCaptured(toolType == null ? "UNKNOWN" : toolType.name(), 1);
        TrafficExportQueue.offer(document);

        pendingOrphans.remove(response.messageId());
        return ResponseReceivedAction.continueWith(response);
    }

    /**
     * Resolves tool type for response handling with fallback to request-side metadata.
     *
     * <p>In some Burp paths, response tool source can be null. Fallback to request-side
     * correlation prevents dropping valid live traffic.</p>
     */
    static ToolType resolveResponseToolType(HttpResponseReceived response, ToolType requestFallbackType) {
        ToolSource responseSource = response == null ? null : response.toolSource();
        ToolType responseType = responseSource == null ? null : responseSource.toolType();
        return responseType != null ? responseType : requestFallbackType;
    }

    /**
     * Builds the traffic document for OpenSearch. Caller must hold Burp HTTP thread.
     *
     * @param response the received response (with initiating request)
     * @param request  the initiating request
     * @param inScope  whether the request passed scope filter
     * @return map matching traffic index mapping (never null)
     */
    Map<String, Object> buildDocument(HttpResponseReceived response, HttpRequest request, boolean inScope) {
        return buildDocument(response, request, inScope, null, null, null);
    }

    Map<String, Object> buildDocument(
            HttpResponseReceived response,
            HttpRequest request,
            boolean inScope,
            Long requestSentMs,
            Long responseReceivedMs,
            ToolType resolvedToolType) {
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = response.toolSource();
        ToolType toolType = resolvedToolType;
        if (toolType == null) {
            toolType = toolSource == null ? null : toolSource.toolType();
        }

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("protocol_transport", scheme);
        document.put("protocol_application", "http");
        document.put("protocol_sub", request.httpVersion());
        document.put("http_version", request.httpVersion());
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("in_scope", inScope);
        document.put("message_id", response.messageId());
        document.put("time_start", toIsoInstant(requestSentMs));
        document.put("time_end", toIsoInstant(responseReceivedMs));
        document.put("duration_ms", durationMs(requestSentMs, responseReceivedMs));
        putAnnotations(document, response.annotations());
        document.put("edited", null);
        document.put("path", request.path());
        document.put("method", request.method());
        document.put("status", (int) response.statusCode());
        MimeType responseMime = response.mimeType();
        document.put("mime_type", responseMime == null ? null : responseMime.name());

        document.put("request", RequestResponseDocBuilder.buildRequestDoc(request));
        document.put("response", RequestResponseDocBuilder.buildResponseDoc(response));

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        document.put("document_meta", meta);
        document.put("proxy_history_id", null);
        document.put("listener_port", null);
        document.put("time_request_sent", toIsoInstant(requestSentMs));
        document.put("response_start_latency_ms", durationMs(requestSentMs, responseReceivedMs));
        document.put("websocket_id", null);
        document.put("ws_direction", null);
        document.put("ws_message_type", null);
        document.put("ws_payload", null);
        document.put("ws_payload_text", null);
        document.put("ws_payload_length", null);
        document.put("ws_edited", null);
        document.put("ws_edited_payload", null);
        document.put("ws_upgrade_request", null);
        document.put("ws_time", null);
        document.put("ws_message_id", null);

        return document;
    }

    private static void putAnnotations(Map<String, Object> document, Annotations annotations) {
        if (annotations == null) {
            return;
        }
        if (annotations.hasNotes()) {
            document.put("comment", annotations.notes());
        }
        if (annotations.hasHighlightColor()) {
            HighlightColor color = annotations.highlightColor();
            document.put("highlight", color == null ? null : color.name());
        }
    }

    /**
     * Builds the document skeleton for an orphaned request (no response received).
     * Caller must hold Burp HTTP thread. Does not include {@code response}; add via
     * {@link #buildOrphanResponse()} when exporting.
     */
    private Map<String, Object> buildOrphanDocumentSkeleton(HttpRequestToBeSent request, long requestSentMs) {
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), request.url(), request.isInScope());

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("protocol_transport", scheme);
        document.put("protocol_application", "http");
        document.put("protocol_sub", request.httpVersion());
        document.put("http_version", request.httpVersion());
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("in_scope", inScope);
        document.put("message_id", request.messageId());
        document.put("time_start", toIsoInstant(requestSentMs));
        document.put("time_end", null);
        document.put("duration_ms", null);
        putAnnotations(document, request.annotations());
        document.put("edited", null);
        document.put("path", request.path());
        document.put("method", request.method());
        document.put("status", ORPHAN_STATUS);
        document.put("mime_type", (String) null);

        document.put("request", RequestResponseDocBuilder.buildRequestDoc(request));

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        document.put("document_meta", meta);
        document.put("proxy_history_id", null);
        document.put("listener_port", null);
        document.put("time_request_sent", toIsoInstant(requestSentMs));
        document.put("response_start_latency_ms", null);
        document.put("websocket_id", null);
        document.put("ws_direction", null);
        document.put("ws_message_type", null);
        document.put("ws_payload", null);
        document.put("ws_payload_text", null);
        document.put("ws_payload_length", null);
        document.put("ws_edited", null);
        document.put("ws_edited_payload", null);
        document.put("ws_upgrade_request", null);
        document.put("ws_time", null);
        document.put("ws_message_id", null);

        return document;
    }

    private static Map<String, Object> buildOrphanResponse() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", ORPHAN_STATUS);
        resp.put("reason_phrase", ORPHAN_REASON_PHRASE);
        resp.put("headers", Collections.emptyList());
        resp.put("cookies", Collections.emptyList());
        resp.put("markers", Collections.emptyList());
        resp.put("header_names", Collections.emptyList());
        return resp;
    }

    /**
     * Runs on a daemon thread. Exports pending requests that have not received a response
     * within {@link #ORPHAN_TIMEOUT_MS} as request-only documents with
     * {@code response.status = 0} and {@code response.reason_phrase = "Timeout"}.
     */
    private static void flushOrphanedRequests() {
        if (!RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isOpenSearchTrafficEnabled()) {
            return;
        }
        String baseUrl = RuntimeConfig.openSearchUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            return;
        }
        long now = System.currentTimeMillis();
        List<Integer> toFlush = new ArrayList<>();
        for (Map.Entry<Integer, PendingOrphan> e : pendingOrphans.entrySet()) {
            if (now - e.getValue().timestamp >= ORPHAN_TIMEOUT_MS) {
                toFlush.add(e.getKey());
            }
        }
        for (Integer messageId : toFlush) {
            PendingOrphan po = pendingOrphans.remove(messageId);
            if (po == null) {
                continue;
            }
            Map<String, Object> doc = new LinkedHashMap<>(po.documentSkeleton);
            long nowMs = System.currentTimeMillis();
            doc.put("time_end", toIsoInstant(nowMs));
            doc.put("duration_ms", durationMs(po.timestamp, nowMs));
            doc.put("response_start_latency_ms", durationMs(po.timestamp, nowMs));
            doc.put("response", buildOrphanResponse());
            long startNs = System.nanoTime();
            boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, doc);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000;
            ExportStats.recordLastPush("traffic", durationMs);
            if (success) {
                ExportStats.recordSuccess("traffic", 1);
                ExportStats.recordTrafficSourceSuccess("proxy_live_http", 1);
            } else {
                ExportStats.recordFailure("traffic", 1);
                ExportStats.recordTrafficSourceFailure("proxy_live_http", 1);
                String errMsg = "Failed to index orphan traffic document to " + INDEX_NAME;
                ExportStats.recordLastError("traffic", errMsg);
                Logger.logError("[OpenSearch] " + errMsg);
            }
        }
    }

    private static final class PendingOrphan {
        final Map<String, Object> documentSkeleton;
        final long timestamp;
        final ToolType toolType;

        PendingOrphan(Map<String, Object> documentSkeleton, long timestamp, ToolType toolType) {
            this.documentSkeleton = documentSkeleton;
            this.timestamp = timestamp;
            this.toolType = toolType;
        }
    }

    private static String toIsoInstant(Long epochMs) {
        if (epochMs == null) {
            return null;
        }
        return Instant.ofEpochMilli(epochMs).toString();
    }

    private static Long durationMs(Long startMs, Long endMs) {
        if (startMs == null || endMs == null) {
            return null;
        }
        long d = endMs - startMs;
        return d >= 0 ? d : 0L;
    }
}