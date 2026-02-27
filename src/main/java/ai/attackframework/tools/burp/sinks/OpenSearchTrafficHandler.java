package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
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
import ai.attackframework.tools.burp.utils.TrafficExportStats;
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
 * <p>Runs on Burp's HTTP thread. Only indexes when OpenSearch traffic export is enabled, the
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

    /**
     * Whether traffic from this tool source should be exported to the traffic index.
     * Only Proxy and Repeater are allowed; all other tools (Scanner, Extensions, etc.) are omitted.
     */
    private static boolean shouldExportTrafficByToolSource(ToolType toolType) {
        return toolType == ToolType.PROXY || toolType == ToolType.REPEATER;
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
        Map<String, Object> skeleton = buildOrphanDocumentSkeleton(request);
        if (skeleton != null) {
            pendingOrphans.put(request.messageId(), new PendingOrphan(skeleton, System.currentTimeMillis()));
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

        ToolSource respToolSource = response.toolSource();
        ToolType respToolType = respToolSource == null ? null : respToolSource.toolType();
        if (!shouldExportTrafficByToolSource(respToolType)) {
            pendingOrphans.remove(response.messageId());
            return ResponseReceivedAction.continueWith(response);
        }

        Map<String, Object> document = buildDocument(response, request, inScope);
        long startNs = System.nanoTime();
        boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, document);
        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
        TrafficExportStats.setLastPushDurationMs(durationMs);

        if (success) {
            TrafficExportStats.incrementSuccess();
        } else {
            TrafficExportStats.incrementFailure();
            String errMsg = "Failed to index traffic document to " + INDEX_NAME;
            TrafficExportStats.setLastError(errMsg);
            Logger.logError("[OpenSearch] " + errMsg);
        }

        pendingOrphans.remove(response.messageId());
        return ResponseReceivedAction.continueWith(response);
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
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = response.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", request.url());
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("http_version", request.httpVersion());
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("in_scope", inScope);
        document.put("message_id", response.messageId());
        putAnnotations(document, response.annotations());
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
        document.put("document_meta", meta);

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
    private Map<String, Object> buildOrphanDocumentSkeleton(HttpRequestToBeSent request) {
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
        document.put("http_version", request.httpVersion());
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("in_scope", inScope);
        document.put("message_id", request.messageId());
        putAnnotations(document, request.annotations());
        document.put("path", request.path());
        document.put("method", request.method());
        document.put("status", ORPHAN_STATUS);
        document.put("mime_type", (String) null);

        document.put("request", RequestResponseDocBuilder.buildRequestDoc(request));

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        document.put("document_meta", meta);

        return document;
    }

    private static Map<String, Object> buildOrphanResponse() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", ORPHAN_STATUS);
        resp.put("reason_phrase", ORPHAN_REASON_PHRASE);
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
            doc.put("response", buildOrphanResponse());
            long startNs = System.nanoTime();
            boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, INDEX_NAME, doc);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000;
            TrafficExportStats.setLastPushDurationMs(durationMs);
            if (success) {
                TrafficExportStats.incrementSuccess();
            } else {
                TrafficExportStats.incrementFailure();
                String errMsg = "Failed to index orphan traffic document to " + INDEX_NAME;
                TrafficExportStats.setLastError(errMsg);
                Logger.logError("[OpenSearch] " + errMsg);
            }
        }
    }

    private static final class PendingOrphan {
        final Map<String, Object> documentSkeleton;
        final long timestamp;

        PendingOrphan(Map<String, Object> documentSkeleton, long timestamp) {
            this.documentSkeleton = documentSkeleton;
            this.timestamp = timestamp;
        }
    }
}