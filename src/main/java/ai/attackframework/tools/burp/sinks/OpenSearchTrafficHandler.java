package ai.attackframework.tools.burp.sinks;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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
 * Shared implementation for live HTTP traffic capture.
 *
 * <p>{@link TrafficHttpHandler} exposes the public sink-neutral type while this package-private
 * support class keeps the larger implementation isolated from the tiny entrypoint wrapper.</p>
 */
class TrafficHttpHandlerSupport implements HttpHandler {

    private static final String SCHEMA_VERSION = "1";

    /** Delay after which a request with no response is exported as an orphan (Chromium-aligned). */
    private static final long ORPHAN_TIMEOUT_MS = 120_000L;
    private static final int ORPHAN_CHECK_INTERVAL_SECONDS = 30;
    /** Sentinel for response when no response was received (e.g. timeout). */
    private static final int ORPHAN_STATUS = 0;
    private static final String ORPHAN_REASON_PHRASE = "Timeout";

    private static final ConcurrentHashMap<Integer, PendingOrphan> pendingOrphans = new ConcurrentHashMap<>();

    private static String trafficIndexName() {
        return RuntimeConfig.indexNameForKey("traffic");
    }

    static {
        ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "attackframework-orphan-export");
            t.setDaemon(true);
            return t;
        });
            exec.scheduleAtFixedRate(
                    TrafficHttpHandlerSupport::flushOrphanedRequests,
                    ORPHAN_CHECK_INTERVAL_SECONDS,
                    ORPHAN_CHECK_INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
    }

    /** Whether traffic from this tool source should be exported (user-selected tool types only). */
    private static boolean shouldExportTrafficByToolSource(ToolType toolType) {
        if (toolType == null) {
            return false;
        }
        return RuntimeConfig.isTrafficToolTypeEnabled(toolType.name());
    }

    /**
     * Whether null/unknown tool-source traffic should be exported.
     *
     * <p>Some Burp flows do not provide tool source on response/request callbacks. We allow these
     * events when Proxy export is enabled so normal browser-driven Proxy traffic is not dropped.</p>
     */
    private static boolean shouldExportNullToolSourceTraffic() {
        return RuntimeConfig.isTrafficToolTypeEnabled("proxy");
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
        if (!RuntimeConfig.isExportReady()
                || !RuntimeConfig.isAnyTrafficExportEnabled()) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!ScopeFilter.shouldExport(
                RuntimeConfig.getState(), safeRequestUrl(request), request.isInScope())) {
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
        RepeaterMetadataFields.Metadata requestStageRepeaterMetadata =
                resolveRequestStageRepeaterMetadata(request, reqToolType);
        Map<String, Object> skeleton = buildOrphanDocumentSkeleton(request, requestSentMs, requestStageRepeaterMetadata);
        if (skeleton != null) {
            pendingOrphans.put(
                    request.messageId(),
                    new PendingOrphan(skeleton, requestSentMs, reqToolType, requestStageRepeaterMetadata));
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!RuntimeConfig.isExportReady()) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (!RuntimeConfig.isAnyTrafficExportEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }

        HttpRequest request = response.initiatingRequest();
        if (request == null) {
            return ResponseReceivedAction.continueWith(response);
        }

        boolean burpInScope = request.isInScope();
        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), safeRequestUrl(request), burpInScope);
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
        ToolType toolType;
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
        RepeaterMetadataFields.Metadata pendingRepeaterMetadata =
                pending == null ? RepeaterMetadataFields.Metadata.empty() : pending.repeaterMetadata;
        RepeaterMetadataFields.Metadata repeaterMetadata =
                resolveResponseStageRepeaterMetadata(request, response, toolType, pendingRepeaterMetadata);

        Map<String, Object> document =
                buildDocument(response, request, burpInScope, requestSentMs, responseReceivedMs, toolType, repeaterMetadata);
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
     * @param burpInScope raw Burp scope state for the request
     * @return map matching traffic index mapping (never null)
     */
    Map<String, Object> buildDocument(HttpResponseReceived response, HttpRequest request, boolean burpInScope) {
        return buildDocument(
                response,
                request,
                burpInScope,
                null,
                null,
                null,
                RepeaterMetadataFields.Metadata.empty());
    }

    Map<String, Object> buildDocument(
            HttpResponseReceived response,
            HttpRequest request,
            boolean burpInScope,
            Long requestSentMs,
            Long responseReceivedMs,
            ToolType resolvedToolType,
            RepeaterMetadataFields.Metadata repeaterMetadata) {
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = response.toolSource();
        ToolType toolType = resolvedToolType;
        if (toolType == null) {
            toolType = toolSource == null ? null : toolSource.toolType();
        }
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildRequestDoc(request);
        Object requestHttpVersion = requestDoc.get("http_version");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", safeRequestUrl(request));
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("protocol_transport", scheme);
        document.put("protocol_application", "http");
        document.put("protocol_sub", requestHttpVersion);
        document.put("http_version", requestHttpVersion);
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("burp_in_scope", burpInScope);
        document.put("message_id", response.messageId());
        document.put("time_start", toIsoInstant(requestSentMs));
        document.put("time_end", toIsoInstant(responseReceivedMs));
        document.put("duration_ms", durationMs(requestSentMs, responseReceivedMs));
        putAnnotations(document, response.annotations());
        document.put("edited", null);
        document.put("path", requestDoc.get("path"));
        document.put("method", requestDoc.get("method"));
        document.put("status", (int) response.statusCode());
        MimeType responseMime = response.mimeType();
        document.put("mime_type", responseMime == null ? null : responseMime.name());
        RepeaterMetadataFields.put(document, repeaterMetadata);

        document.put("request", requestDoc);
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
    private Map<String, Object> buildOrphanDocumentSkeleton(
            HttpRequestToBeSent request,
            long requestSentMs,
            RepeaterMetadataFields.Metadata repeaterMetadata) {
        HttpService service = request.httpService();
        String scheme = service == null ? null : (service.secure() ? "https" : "http");
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        boolean burpInScope = request.isInScope();
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildRequestDoc(request);
        Object requestHttpVersion = requestDoc.get("http_version");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", safeRequestUrl(request));
        document.put("host", service == null ? null : service.host());
        document.put("port", service == null ? null : service.port());
        document.put("scheme", scheme);
        document.put("protocol_transport", scheme);
        document.put("protocol_application", "http");
        document.put("protocol_sub", requestHttpVersion);
        document.put("http_version", requestHttpVersion);
        document.put("tool", toolType == null ? null : toolType.toolName());
        document.put("tool_type", toolType == null ? null : toolType.name());
        document.put("burp_in_scope", burpInScope);
        document.put("message_id", request.messageId());
        document.put("time_start", toIsoInstant(requestSentMs));
        document.put("time_end", null);
        document.put("duration_ms", null);
        putAnnotations(document, request.annotations());
        document.put("edited", null);
        document.put("path", requestDoc.get("path"));
        document.put("method", requestDoc.get("method"));
        document.put("status", ORPHAN_STATUS);
        document.put("mime_type", (String) null);
        RepeaterMetadataFields.put(document, repeaterMetadata);

        document.put("request", requestDoc);

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

    /**
     * Returns the request URL when Montoya exposes it safely.
     *
     * <p>Malformed or partially bound Repeater requests can throw from {@code request.url()}.
     * Returning {@code null} lets scope checks and document assembly keep the rest of the request
     * instead of dropping the document.</p>
     */
    private static String safeRequestUrl(HttpRequest request) {
        try {
            return request == null ? null : request.url();
        } catch (RuntimeException e) {
            Logger.logDebug("[TrafficHttpHandler] Failed to resolve request URL: " + e.getMessage());
            return null;
        }
    }

    /**
     * Resolves best-effort Repeater metadata during the request stage.
     *
     * <p>Only live {@link ToolType#REPEATER} traffic participates. Ambiguous tracker matches
     * intentionally return empty metadata so identical concurrent Repeater tabs do not inherit the
     * wrong label from current UI focus.</p>
     */
    static RepeaterMetadataFields.Metadata resolveRequestStageRepeaterMetadata(HttpRequest request, ToolType toolType) {
        return resolveRequestStageRepeaterMetadata(
                request,
                toolType,
                RepeaterHistoryIndexReporter::currentRepeaterSharedMetadataForLiveFallback);
    }

    /**
     * Resolves best-effort Repeater metadata during the request stage.
     *
     * @param request live request being exported
     * @param toolType Burp tool that emitted the request
     * @param liveFallbackSupplier current UI metadata supplier used only when no tracked match exists
     * @return best-effort Repeater metadata or {@link RepeaterMetadataFields.Metadata#empty()}
     */
    static RepeaterMetadataFields.Metadata resolveRequestStageRepeaterMetadata(
            HttpRequest request,
            ToolType toolType,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        if (toolType != ToolType.REPEATER) {
            return RepeaterMetadataFields.Metadata.empty();
        }
        return resolveTrackedRequestOrLiveFallback(request, "request", liveFallbackSupplier);
    }

    /**
     * Resolves best-effort Repeater metadata during the response stage.
     *
     * <p>The response stage first tries the stricter request+response tracker match, then reuses
     * confident request-stage metadata, and finally consults the current UI only when there was no
     * tracked signal at all.</p>
     */
    static RepeaterMetadataFields.Metadata resolveResponseStageRepeaterMetadata(
            HttpRequest request,
            HttpResponseReceived response,
            ToolType toolType,
            RepeaterMetadataFields.Metadata requestStageMetadata) {
        return resolveResponseStageRepeaterMetadata(
                request,
                response,
                toolType,
                requestStageMetadata,
                RepeaterHistoryIndexReporter::currentRepeaterSharedMetadataForLiveFallback);
    }

    /**
     * Resolves best-effort Repeater metadata during the response stage.
     *
     * @param request live request being exported
     * @param response live response being exported
     * @param toolType Burp tool that emitted the exchange
     * @param requestStageMetadata confident metadata captured earlier during request export
     * @param liveFallbackSupplier current UI metadata supplier used only when no tracked match exists
     * @return best-effort Repeater metadata or {@link RepeaterMetadataFields.Metadata#empty()}
     */
    static RepeaterMetadataFields.Metadata resolveResponseStageRepeaterMetadata(
            HttpRequest request,
            HttpResponseReceived response,
            ToolType toolType,
            RepeaterMetadataFields.Metadata requestStageMetadata,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        if (toolType != ToolType.REPEATER) {
            return RepeaterMetadataFields.Metadata.empty();
        }
        RepeaterLiveMetadataTracker.Resolution exchangeResolution =
                RepeaterLiveMetadataTracker.resolveExchangeResolution(request, response);
        if (exchangeResolution.metadata().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    "response",
                    exchangeResolution.sourceLabel(),
                    exchangeResolution.metadata(),
                    "reason=tracker_match");
            return exchangeResolution.metadata();
        }
        if (exchangeResolution.ambiguous()) {
            if (requestStageMetadata != null && requestStageMetadata.isPresent()) {
                logLiveRepeaterMetadataDecision(
                        "response",
                        RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE,
                        requestStageMetadata,
                        "reason=exchange_ambiguous trackerSource="
                                + RepeaterMetadataTraceLabels.safeValue(exchangeResolution.sourceLabel()));
                return requestStageMetadata;
            }
            logLiveRepeaterMetadataDecision(
                    "response",
                    RepeaterMetadataTraceLabels.AMBIGUOUS_NULL,
                    RepeaterMetadataFields.Metadata.empty(),
                    "reason=exchange_ambiguous trackerSource="
                            + RepeaterMetadataTraceLabels.safeValue(exchangeResolution.sourceLabel()));
            return RepeaterMetadataFields.Metadata.empty();
        }
        if (requestStageMetadata != null && requestStageMetadata.isPresent()) {
            logLiveRepeaterMetadataDecision(
                    "response",
                    RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE,
                    requestStageMetadata,
                    "reason=exchange_tracker_miss");
            return requestStageMetadata;
        }
        return resolveTrackedRequestOrLiveFallback(request, "response", liveFallbackSupplier);
    }

    /**
     * Resolves Repeater metadata from the short-lived tracker before touching the Swing fallback.
     *
     * <p>The tracker is the authoritative source for live Repeater traffic because it is bound to
     * the observed request object. The fallback supplier is only consulted when there is no tracked
     * match. When the tracker sees multiple distinct metadata candidates for the same live request,
     * this helper returns empty metadata instead of querying the current UI selection so ambiguous
     * concurrent traffic does not inherit the wrong tab/group name.</p>
     */
    private static RepeaterMetadataFields.Metadata resolveTrackedRequestOrLiveFallback(
            HttpRequest request,
            String stage,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        RepeaterLiveMetadataTracker.Resolution trackedRequest =
                RepeaterLiveMetadataTracker.resolveRequestResolution(request);
        if (trackedRequest.metadata().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    stage,
                    trackedRequest.sourceLabel(),
                    trackedRequest.metadata(),
                    "reason=tracker_match");
            return trackedRequest.metadata();
        }
        if (trackedRequest.ambiguous()) {
            logLiveRepeaterMetadataDecision(
                    stage,
                    RepeaterMetadataTraceLabels.AMBIGUOUS_NULL,
                    RepeaterMetadataFields.Metadata.empty(),
                    "reason=request_ambiguous trackerSource="
                            + RepeaterMetadataTraceLabels.safeValue(trackedRequest.sourceLabel()));
            return RepeaterMetadataFields.Metadata.empty();
        }
        RepeaterMetadataFields.Metadata fallbackMetadata = liveFallbackSupplier == null
                ? RepeaterMetadataFields.Metadata.empty()
                : liveFallbackSupplier.get();
        RepeaterMetadataFields.Metadata normalizedFallback =
                fallbackMetadata == null ? RepeaterMetadataFields.Metadata.empty() : fallbackMetadata;
        logLiveRepeaterMetadataDecision(
                stage,
                RepeaterMetadataTraceLabels.UI_FALLBACK,
                normalizedFallback,
                normalizedFallback.isPresent()
                        ? "reason=no_tracked_match"
                        : "reason=no_tracked_match_and_ui_unlabeled");
        return normalizedFallback;
    }

    private static void logLiveRepeaterMetadataDecision(
            String stage,
            String metadataSource,
            RepeaterMetadataFields.Metadata metadata,
            String reason) {
        ExportStats.recordRepeaterMetadataSource(metadataSource);
        Logger.logTrace("[TrafficHttpHandler] Live Repeater metadata stage="
                + RepeaterMetadataTraceLabels.safeValue(stage)
                + " metadataSource=" + RepeaterMetadataTraceLabels.safeValue(metadataSource)
                + " " + RepeaterMetadataTraceLabels.describeLiveMetadata(metadata)
                + " " + RepeaterMetadataTraceLabels.safeValue(reason));
    }

    private static Map<String, Object> buildOrphanResponse() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", ORPHAN_STATUS);
        resp.put("status_code_class", null);
        resp.put("reason_phrase", ORPHAN_REASON_PHRASE);
        resp.put("http_version", null);
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("full", List.of());
        headers.put("names", List.of());
        headers.put("etag", null);
        headers.put("last_modified", null);
        headers.put("content_location", null);
        resp.put("headers", headers);
        resp.put("cookies", Collections.emptyList());
        resp.put("mime_type", null);
        resp.put("stated_mime_type", null);
        resp.put("inferred_mime_type", null);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", 0);
        body.put("offset", 0);
        body.put("b64", null);
        body.put("text", null);
        resp.put("body", body);
        resp.put("markers", Collections.emptyList());
        return resp;
    }

    /**
     * Runs on a daemon thread. Exports pending requests that have not received a response
     * within {@link #ORPHAN_TIMEOUT_MS} as request-only documents with
     * {@code response.status = 0} and {@code response.reason_phrase = "Timeout"}.
     */
    private static void flushOrphanedRequests() {
        if (!RuntimeConfig.isExportReady()
                || !RuntimeConfig.isAnyTrafficExportEnabled()) {
            return;
        }
        String baseUrl = RuntimeConfig.openSearchUrl();
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
            boolean success = OpenSearchClientWrapper.pushDocument(baseUrl, trafficIndexName(), "traffic", doc);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000;
            boolean openSearchActive = baseUrl != null && !baseUrl.isBlank();
            if (openSearchActive) {
                ExportStats.recordLastPush("traffic", durationMs);
            }
            if (success && openSearchActive) {
                ExportStats.recordSuccess("traffic", 1);
                ExportStats.recordTrafficSourceSuccess("proxy_live_http", 1);
            } else if (!success && openSearchActive) {
                ExportStats.recordFailure("traffic", 1);
                ExportStats.recordTrafficSourceFailure("proxy_live_http", 1);
                String errMsg = "Failed to index orphan traffic document to " + trafficIndexName();
                ExportStats.recordLastError("traffic", errMsg);
                Logger.logError("[OpenSearch] " + errMsg);
            }
        }
    }

    private static final class PendingOrphan {
        final Map<String, Object> documentSkeleton;
        final long timestamp;
        final ToolType toolType;
        final RepeaterMetadataFields.Metadata repeaterMetadata;

        PendingOrphan(
                Map<String, Object> documentSkeleton,
                long timestamp,
                ToolType toolType,
                RepeaterMetadataFields.Metadata repeaterMetadata) {
            this.documentSkeleton = documentSkeleton;
            this.timestamp = timestamp;
            this.toolType = toolType;
            this.repeaterMetadata = repeaterMetadata == null
                    ? RepeaterMetadataFields.Metadata.empty()
                    : repeaterMetadata;
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