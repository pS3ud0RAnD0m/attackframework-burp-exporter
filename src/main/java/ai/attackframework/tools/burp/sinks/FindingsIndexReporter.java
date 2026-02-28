package ai.attackframework.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
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

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.ScopeFilter;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
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
    private static final int BULK_BATCH_SIZE = 100;
    /** Flush when batch exceeds this approximate payload size (bytes) so large request/response bodies don't produce huge bulk requests. */
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024; // 5 MB
    private static final String FINDINGS_INDEX = IndexNaming.INDEX_PREFIX + "-findings";
    private static final String SCHEMA_VERSION = "1";
    private static final int BODY_BASE64_MAX_BYTES = 32_768;

    private static volatile ScheduledExecutorService scheduler;
    /** Keys of issues already pushed this session; only push new on 30s run. */
    private static final Set<String> pushedIssueKeys = ConcurrentHashMap.newKeySet();
    private static volatile boolean runInProgress;

    private FindingsIndexReporter() {}

    /**
     * Pushes all current issues once (e.g. initial push on Start). Safe to call
     * from any thread. No-op if export is not running, OpenSearch URL is blank,
     * or Issues is not in the selected data sources.
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_FINDINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            if (scheduler != null) {
                scheduler.submit(() -> pushIssues(api, baseUrl, true));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Findings index: push failed: " + msg);
        }
    }

    /**
     * Starts the 30-second scheduler. Does not perform an initial push (caller
     * must call {@link #pushSnapshotNow()} once on Start). Safe to call from any thread.
     */
    public static void start() {
        if (scheduler != null) {
            return;
        }
        synchronized (FindingsIndexReporter.class) {
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "attackframework-findings-reporter");
                t.setDaemon(true);
                return t;
            });
            exec.scheduleAtFixedRate(
                    FindingsIndexReporter::pushNewIssuesOnly,
                    INTERVAL_SECONDS,
                    INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
            scheduler = exec;
        }
    }

    static void pushNewIssuesOnly() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_FINDINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushIssues(api, baseUrl, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logDebug("Findings index: push failed: " + msg);
        }
    }

    private static void pushIssues(MontoyaApi api, String baseUrl, boolean pushAll) {
        if (runInProgress) {
            return;
        }
        runInProgress = true;
        try {
            List<AuditIssue> issues = api.siteMap().issues();
            if (issues == null) {
                return;
            }
            var state = RuntimeConfig.getState();
            List<String> batchKeys = new ArrayList<>(BULK_BATCH_SIZE);
            List<Map<String, Object>> batchDocs = new ArrayList<>(BULK_BATCH_SIZE);
            long runningBatchBytes = 0;

            for (AuditIssue issue : issues) {
                String issueUrl = issue.baseUrl() != null ? issue.baseUrl() : "";
                boolean burpInScope = api.scope().isInScope(issueUrl);
                if (!ScopeFilter.shouldExport(state, issueUrl, burpInScope)) {
                    continue;
                }
                String key = issueKey(issue);
                if (!pushAll && pushedIssueKeys.contains(key)) {
                    continue;
                }
                Map<String, Object> doc = buildFindingDoc(issue);
                if (doc == null) {
                    continue;
                }
                batchKeys.add(key);
                batchDocs.add(doc);
                runningBatchBytes += BulkPayloadEstimator.estimateBytes(doc);

                if (batchDocs.size() >= BULK_BATCH_SIZE || runningBatchBytes >= BULK_MAX_BYTES) {
                    flushBatch(baseUrl, batchKeys, batchDocs);
                    batchKeys.clear();
                    batchDocs.clear();
                    runningBatchBytes = 0;
                }
            }
            if (!batchDocs.isEmpty()) {
                flushBatch(baseUrl, batchKeys, batchDocs);
            }
        } finally {
            runInProgress = false;
        }
    }

    private static void flushBatch(String baseUrl, List<String> batchKeys, List<Map<String, Object>> batchDocs) {
        int successCount = OpenSearchClientWrapper.pushBulk(baseUrl, FINDINGS_INDEX, batchDocs);
        if (successCount == batchDocs.size()) {
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

    private static Map<String, Object> buildFindingDoc(AuditIssue issue) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("name", nullToEmpty(issue.name()));
        AuditIssueSeverity severity = issue.severity();
        doc.put("severity", severity != null ? severity.name() : "");
        AuditIssueConfidence confidence = issue.confidence();
        doc.put("confidence", confidence != null ? confidence.name() : "");

        HttpService svc = issue.httpService();
        doc.put("host", svc != null ? svc.host() : "");
        doc.put("port", svc != null ? svc.port() : 0);
        doc.put("protocol_transport", svc != null ? (svc.secure() ? "https" : "http") : "");
        doc.put("protocol_application", "");
        doc.put("protocol_sub", "");
        doc.put("url", nullToEmpty(issue.baseUrl()));
        doc.put("param", "");

        try {
            var def = issue.definition();
            if (def != null) {
                doc.put("issue_type_id", def.typeIndex());
                AuditIssueSeverity typical = def.typicalSeverity();
                doc.put("typical_severity", typical != null ? typical.name() : "");
                doc.put("background", nullToEmpty(def.background()));
                doc.put("remediation_background", nullToEmpty(def.remediation()));
            } else {
                doc.put("issue_type_id", 0);
                doc.put("typical_severity", "");
                doc.put("background", "");
                doc.put("remediation_background", "");
            }
        } catch (Exception e) {
            doc.put("issue_type_id", 0);
            doc.put("typical_severity", "");
            doc.put("background", "");
            doc.put("remediation_background", "");
        }

        doc.put("description", nullToEmpty(issue.detail()));
        doc.put("remediation_detail", nullToEmpty(issue.remediation()));
        doc.put("references", "");
        Map<String, Object> classifications = new LinkedHashMap<>();
        doc.put("classifications", classifications);

        List<HttpRequestResponse> reqResList = issue.requestResponses();
        boolean missingReqRes = reqResList == null || reqResList.isEmpty();
        doc.put("request_responses_missing", missingReqRes);
        List<Map<String, Object>> requestResponsesList = new ArrayList<>();
        if (!missingReqRes && reqResList != null) {
            for (HttpRequestResponse rr : reqResList) {
                HttpRequest req = rr.request();
                if (req == null) {
                    continue;
                }
                HttpResponse resp = rr.hasResponse() ? rr.response() : null;
                Map<String, Object> reqDoc = RequestResponseDocBuilder.buildRequestDoc(req);
                Map<String, Object> respDoc = resp != null ? RequestResponseDocBuilder.buildResponseDoc(resp) : emptyResponseDoc();
                applyBodyCap(reqDoc);
                applyBodyCap(respDoc);
                Map<String, Object> pair = new LinkedHashMap<>();
                pair.put("request", reqDoc);
                pair.put("response", respDoc);
                requestResponsesList.add(pair);
            }
        }
        doc.put("request_responses", requestResponsesList);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        doc.put("document_meta", meta);
        return doc;
    }

    private static void applyBodyCap(Map<String, Object> reqOrResp) {
        Object bodyObj = reqOrResp.get("body");
        if (bodyObj instanceof String base64) {
            int decodedLen = Base64.getDecoder().decode(base64).length;
            if (decodedLen > BODY_BASE64_MAX_BYTES) {
                reqOrResp.put("body", null);
                reqOrResp.put("body_content", null);
            }
        }
    }

    private static Map<String, Object> emptyResponseDoc() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", 0);
        m.put("status_code_class", null);
        m.put("reason_phrase", null);
        m.put("http_version", null);
        m.put("headers", List.of());
        m.put("cookies", List.of());
        m.put("mime_type", null);
        m.put("stated_mime_type", null);
        m.put("inferred_mime_type", null);
        m.put("body", null);
        m.put("body_length", 0);
        m.put("body_content", null);
        m.put("body_offset", 0);
        m.put("markers", List.of());
        return m;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
