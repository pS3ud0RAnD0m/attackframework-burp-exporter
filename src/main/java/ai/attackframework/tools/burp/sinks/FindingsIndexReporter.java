package ai.attackframework.tools.burp.sinks;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Pushes Burp audit issues (findings) to the findings index when export is
 * running and "Issues" is selected. Initial push on Start; every 30 seconds
 * pushes only issues not yet sent. Does not start a new run while the previous
 * is still in progress.
 */
public final class FindingsIndexReporter {

    private static final int INTERVAL_SECONDS = 30;
    /** Flush when batch exceeds this approximate payload size (bytes) so large request/response bodies don't produce huge bulk requests. */
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024; // 5 MB
    private static final String SCHEMA_VERSION = "1";
    private static final String REPORTING_TOOL = "Scanner";

    /**
     * Single-owner scheduler for findings push work.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} on {@link #start()} and torn down
     * by {@link #stop()} during UI stop or extension unload. A subsequent {@link #start()} or
     * {@link #pushSnapshotNow()} lazily recreates the executor.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-findings-reporter");
    /** Keys of issues already pushed this session; only push new on 30s run. */
    private static final Set<String> pushedIssueKeys = ConcurrentHashMap.newKeySet();
    private static final AtomicBoolean issuesAccessFailureLogged = new AtomicBoolean();
    private static volatile boolean runInProgress;

    private FindingsIndexReporter() {}

    private static String findingsIndexName() {
        return RuntimeConfig.indexNameForKey("findings");
    }

    /**
     * Pushes all current issues once (e.g. initial push on Start). Safe to call
     * from any thread. No-op if export is not running, no sink is enabled,
     * or Issues is not in the selected data sources.
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_FINDINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            ScheduledExecutorService exec = SCHEDULER.peek();
            if (exec != null) {
                exec.submit(() -> pushIssues(api, true));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[Findings] Snapshot push failed: " + msg);
        }
    }

    /**
     * Starts the 30-second scheduler. Does not perform an initial push (caller
     * must call {@link #pushSnapshotNow()} once on Start). Safe to call from any thread.
     */
    public static void start() {
        SCHEDULER.startRecurring(
                FindingsIndexReporter::pushNewIssuesOnly,
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
        pushedIssueKeys.clear();
        issuesAccessFailureLogged.set(false);
        runInProgress = false;
    }

    static void pushNewIssuesOnly() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_FINDINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushIssues(api, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[Findings] Periodic push failed: " + msg);
        }
    }

    private static void pushIssues(MontoyaApi api, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<AuditIssue> issues = safeIssues(api);
            if (issues == null) {
                return;
            }
            var state = RuntimeConfig.getState();
            int batchSize = BatchSizeController.getInstance().getCurrentBatchSize();
            List<String> batchKeys = new ArrayList<>(batchSize);
            List<Map<String, Object>> batchDocs = new ArrayList<>(batchSize);
            long runningBatchBytes = 0;

            var severities = state.findingsSeverities();
            boolean filterBySeverity = severities != null && !severities.isEmpty();
            Set<String> selectedSeverities = filterBySeverity ? Set.copyOf(severities) : Set.of();

            for (AuditIssue issue : issues) {
                if (!RuntimeConfig.isExportRunning()) {
                    break;
                }
                if (filterBySeverity) {
                    AuditIssueSeverity sev = issue.severity();
                    if (sev == null || !selectedSeverities.contains(sev.name().toLowerCase(java.util.Locale.ROOT))) {
                        continue;
                    }
                }
                String issueUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
                boolean burpInScope = safeBurpInScope(api, issueUrl);
                if (!ScopeFilter.shouldExport(state, issueUrl, burpInScope)) {
                    continue;
                }
                String key = issueKey(issue);
                if (!pushAll && pushedIssueKeys.contains(key)) {
                    continue;
                }
                Map<String, Object> doc = buildFindingDoc(issue, burpInScope);
                if (doc == null) {
                    continue;
                }
                batchKeys.add(key);
                batchDocs.add(doc);
                runningBatchBytes += BulkPayloadEstimator.estimateBytes(doc);

                if (batchDocs.size() >= BatchSizeController.getInstance().getCurrentBatchSize() || runningBatchBytes >= BULK_MAX_BYTES) {
                    flushBatch(batchKeys, batchDocs);
                    batchKeys.clear();
                    batchDocs.clear();
                    runningBatchBytes = 0;
                }
            }
            if (RuntimeConfig.isExportRunning() && !batchDocs.isEmpty()) {
                flushBatch(batchKeys, batchDocs);
            }
        } finally {
            runInProgress = false;
        }
    }

    /** Returns current Burp issues, tolerating transient lifecycle nulls. */
    private static List<AuditIssue> safeIssues(MontoyaApi api) {
        try {
            if (api == null) {
                return null;
            }
            var siteMap = api.siteMap();
            if (siteMap == null) {
                return null;
            }
            return siteMap.issues();
        } catch (Throwable t) {
            logIssuesAccessFailureOnce(t);
            return null;
        }
    }

    private static void logIssuesAccessFailureOnce(Throwable t) {
        if (!issuesAccessFailureLogged.compareAndSet(false, true)) {
            return;
        }
        String msg = t != null && t.getMessage() != null ? t.getMessage() : t != null ? t.getClass().getSimpleName() : "unknown error";
        Logger.logDebug("[Findings] siteMap().issues() unavailable; skipping findings export until access succeeds: " + msg);
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

    private static void flushBatch(List<String> batchKeys, List<Map<String, Object>> batchDocs) {
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        int attempted = batchDocs.size();
        int successCount = OpenSearchClientWrapper.pushBulk(activeBaseUrl, findingsIndexName(), "findings", batchDocs);
        BulkOutcomeRecorder.record("findings", "Findings", "Bulk push", attempted, successCount, openSearchActive);
        if (successCount == attempted) {
            pushedIssueKeys.addAll(batchKeys);
        }
    }

    private static String issueKey(AuditIssue issue) {
        String name = issue.name() != null ? issue.name() : "";
        String baseUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
        HttpService svc = issue.httpService();
        String host = svc != null ? svc.host() : "";
        int port = svc != null ? svc.port() : 0;
        AuditIssueSeverity sev = issue.severity();
        String severity = sev != null ? sev.name() : "";
        String detail = issue.detail() != null ? issue.detail() : "";
        String raw = name + "|" + baseUrl + "|" + host + "|" + port + "|" + severity + "|" + detail;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(raw.hashCode());
        }
    }

    static Map<String, Object> buildFindingDoc(AuditIssue issue) {
        return buildFindingDoc(issue, false);
    }

    private static Map<String, Object> buildFindingDoc(AuditIssue issue, boolean burpInScope) {
        Map<String, Object> doc = new LinkedHashMap<>();
        HttpService svc = issue.httpService();
        doc.put("burp", buildRootBurpDoc(burpInScope));
        doc.put("issue", buildIssueDoc(issue));
        doc.put("target", buildTargetDoc(issue, svc));

        List<HttpRequestResponse> reqResList = issue.requestResponses();
        boolean missingReqRes = reqResList == null || reqResList.isEmpty();
        List<Map<String, Object>> requestResponsesList = new ArrayList<>();
        if (!missingReqRes && reqResList != null) {
            for (HttpRequestResponse rr : reqResList) {
                if (rr == null) {
                    continue;
                }
                HttpRequest req = rr.request();
                if (req == null) {
                    continue;
                }
                HttpResponse resp = rr.hasResponse() ? rr.response() : null;
                HttpService pairService = pairHttpService(rr, svc);
                Map<String, Object> reqDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(req);
                putPairRequestServiceFields(reqDoc, req, pairService);
                Map<String, Object> respDoc = resp != null
                        ? RequestResponseDocBuilder.buildTrafficResponseDoc(resp)
                        : emptyTrafficResponseDoc();
                // Scanner-attached pair-level markers (issue evidence) take precedence over the
                // per-message marker slots filled by RequestResponseDocBuilder, since for
                // scanner-produced findings the per-message markers are essentially always empty
                // and the evidence highlights live on the HttpRequestResponse pair itself.
                TrafficPairMarkers.overlayPairMarkers(reqDoc, respDoc, rr);
                Map<String, Object> pair = new LinkedHashMap<>();
                pair.put("burp", buildPairBurpDoc(rr));
                pair.put("request", reqDoc);
                pair.put("response", respDoc);
                requestResponsesList.add(pair);
            }
        }
        doc.put("requests_responses", requestResponsesList);
        doc.put("collaborator", buildCollaboratorInteractionsList(issue));

        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    private static Map<String, Object> buildRootBurpDoc(boolean burpInScope) {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("is_in_scope", burpInScope);
        burp.put("reporting_tool", REPORTING_TOOL);
        return burp;
    }

    private static Map<String, Object> buildIssueDoc(AuditIssue issue) {
        Map<String, Object> issueDoc = new LinkedHashMap<>();
        issueDoc.put("name", nullToEmpty(issue.name()));
        AuditIssueSeverity severity = issue.severity();
        issueDoc.put("severity", severity != null ? severity.name() : "");
        AuditIssueConfidence confidence = issue.confidence();
        issueDoc.put("confidence", confidence != null ? confidence.name() : "");

        Map<String, Object> remediation = new LinkedHashMap<>();
        try {
            var def = issue.definition();
            if (def != null) {
                issueDoc.put("type_id", def.typeIndex());
                AuditIssueSeverity typical = def.typicalSeverity();
                issueDoc.put("typical_severity", typical != null ? typical.name() : "");
                issueDoc.put("background", nullToEmpty(def.background()));
                remediation.put("background", nullToEmpty(def.remediation()));
            } else {
                issueDoc.put("type_id", 0);
                issueDoc.put("typical_severity", "");
                issueDoc.put("background", "");
                remediation.put("background", "");
            }
        } catch (RuntimeException e) {
            issueDoc.put("type_id", 0);
            issueDoc.put("typical_severity", "");
            issueDoc.put("background", "");
            remediation.put("background", "");
        }

        issueDoc.put("description", nullToEmpty(issue.detail()));
        remediation.put("detail", nullToEmpty(issue.remediation()));
        issueDoc.put("remediation", remediation);
        return issueDoc;
    }

    private static Map<String, Object> buildTargetDoc(AuditIssue issue, HttpService svc) {
        Map<String, Object> target = new LinkedHashMap<>();
        target.put("url", nullToEmpty(issue.baseUrl()));
        target.put("host", svc != null ? svc.host() : "");
        target.put("port", svc != null ? svc.port() : 0);

        Map<String, Object> protocol = new LinkedHashMap<>();
        protocol.put("scheme", svc != null ? (svc.secure() ? "https" : "http") : "");
        target.put("protocol", protocol);
        return target;
    }

    private static void putPairRequestServiceFields(
            Map<String, Object> reqDoc, HttpRequest request, HttpService service) {
        if (reqDoc == null) {
            return;
        }
        String url = RequestResponseDocBuilder.buildBestEffortUrl(request, service, reqDoc, "Findings");
        reqDoc.put("url", nullToEmpty(url));
        reqDoc.put("port", service == null ? null : service.port());
        reqDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                service == null ? null : (service.secure() ? "https" : "http"),
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));
    }

    private static HttpService pairHttpService(HttpRequestResponse rr, HttpService fallback) {
        try {
            HttpService service = rr.httpService();
            return service != null ? service : fallback;
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    /** Builds the pair-level Burp metadata sub-document for one {@link HttpRequestResponse}. */
    private static Map<String, Object> buildPairBurpDoc(HttpRequestResponse rr) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timing", BurpTimingFields.from(rr));
        Annotations ann = rr == null ? null : rr.annotations();
        if (ann == null) {
            m.put("notes", null);
            m.put("highlight", null);
            return m;
        }
        m.put("notes", ann.hasNotes() ? ann.notes() : null);
        HighlightColor hl = ann.hasHighlightColor() ? ann.highlightColor() : null;
        m.put("highlight", hl != null ? hl.name() : null);
        return m;
    }

    /**
     * Captures Burp Collaborator interactions associated with the issue, including the
     * forensic-preserving raw HTTP request/response bytes for HTTP pingbacks.
     *
     * <p>HTTP request/response bodies for collaborator pingbacks are typically small (the
     * payload Burp Suite's mock listener returns) and base64-encoding them preserves the
     * original bytes verbatim for downstream forensic analysis without requiring the
     * findings mapping to enumerate the full HTTP document shape twice. Larger or richer
     * parsed representations can be added later if specific queries require them.</p>
     */
    private static List<Map<String, Object>> buildCollaboratorInteractionsList(AuditIssue issue) {
        List<Interaction> interactions;
        try {
            interactions = issue.collaboratorInteractions();
        } catch (RuntimeException ignored) {
            return List.of();
        }
        if (interactions == null || interactions.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>(interactions.size());
        for (Interaction i : interactions) {
            if (i == null) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", i.id() != null ? i.id().toString() : null);
            entry.put("type", i.type() != null ? i.type().name() : null);
            entry.put("time", i.timeStamp() != null ? i.timeStamp().toInstant().toString() : null);
            InetAddress ip = i.clientIp();
            entry.put("client_ip", ip != null ? ip.getHostAddress() : null);
            entry.put("client_port", i.clientPort());

            Map<String, Object> dns = new LinkedHashMap<>();
            Optional<DnsDetails> dnsOpt = i.dnsDetails();
            if (dnsOpt.isPresent()) {
                DnsDetails d = dnsOpt.get();
                dns.put("query_type", d.queryType() != null ? d.queryType().name() : null);
                ByteArray q = d.query();
                dns.put("query_b64", q != null ? Base64.getEncoder().encodeToString(q.getBytes()) : null);
            }
            entry.put("dns", dns);

            Map<String, Object> http = new LinkedHashMap<>();
            Optional<HttpDetails> httpOpt = i.httpDetails();
            if (httpOpt.isPresent()) {
                HttpDetails h = httpOpt.get();
                http.put("protocol", h.protocol() != null ? h.protocol().name() : null);
                HttpRequestResponse hrr = h.requestResponse();
                if (hrr != null) {
                    Map<String, Object> requestDoc = null;
                    Map<String, Object> responseDoc;
                    HttpRequest hreq = hrr.request();
                    if (hreq != null) {
                        ByteArray bytes = hreq.toByteArray();
                        http.put("request_b64", bytes != null ? Base64.getEncoder().encodeToString(bytes.getBytes()) : null);
                        requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(hreq);
                        putPairRequestServiceFields(requestDoc, hreq, pairHttpService(hrr, null));
                    }
                    HttpResponse hresp = hrr.hasResponse() ? hrr.response() : null;
                    if (hresp != null) {
                        ByteArray bytes = hresp.toByteArray();
                        http.put("response_b64", bytes != null ? Base64.getEncoder().encodeToString(bytes.getBytes()) : null);
                        responseDoc = RequestResponseDocBuilder.buildTrafficResponseDoc(hresp);
                    } else {
                        responseDoc = emptyTrafficResponseDoc();
                    }
                    TrafficPairMarkers.overlayPairMarkers(requestDoc, responseDoc, hrr);
                    if (requestDoc != null) {
                        http.put("request", requestDoc);
                    }
                    http.put("response", responseDoc);
                }
            }
            entry.put("http", http);

            Map<String, Object> smtp = new LinkedHashMap<>();
            Optional<SmtpDetails> smtpOpt = i.smtpDetails();
            if (smtpOpt.isPresent()) {
                SmtpDetails s = smtpOpt.get();
                smtp.put("protocol", s.protocol() != null ? s.protocol().name() : null);
                smtp.put("conversation", s.conversation());
            }
            entry.put("smtp", smtp);

            Optional<String> custom = i.customData();
            entry.put("custom_data", custom.orElse(null));
            out.add(entry);
        }
        return out;
    }

    private static Map<String, Object> emptyTrafficResponseDoc() {
        Map<String, Object> response = new LinkedHashMap<>();

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("code", null);
        status.put("code_class", null);
        status.put("description", null);
        response.put("status", status);

        Map<String, Object> protocol = new LinkedHashMap<>();
        protocol.put("http_version", null);
        response.put("protocol", protocol);

        response.put("header", new LinkedHashMap<String, Object>());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", 0);
        body.put("offset", 0);
        body.put("b64", null);
        body.put("text", null);
        body.put("markers", List.of());
        response.put("body", body);

        return response;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
