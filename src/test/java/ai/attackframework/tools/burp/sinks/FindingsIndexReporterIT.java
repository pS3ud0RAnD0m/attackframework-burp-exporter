package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.OpenSearchTestConfig;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;

/**
 * Integration test: {@link FindingsIndexReporter} pushes a document to the
 * findings index when export is running and Burp API supplies issues. Uses
 * real OpenSearch at {@value #BASE_URL}; mocks MontoyaApi and siteMap().issues().
 * Verifies document shape after round-trip. Run with full test task or exclude
 * with {@code -PexcludeIntegration} to skip.
 */
@Tag("integration")
class FindingsIndexReporterIT {

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;

    private static final String ISSUE_NAME = "SQL injection";
    private static final String ISSUE_BASE_URL = "https://example.com/page";
    private static final String ISSUE_HOST = "example.com";
    private static final int ISSUE_PORT = 443;
    private static final String ISSUE_DETAIL = "Parameter id is vulnerable.";
    private static final String ISSUE_REMEDIATION = "Use parameterized queries.";
    private static final String DEF_BACKGROUND = "SQL injection allows...";
    private static final String DEF_REMEDIATION = "Use prepared statements.";
    private static final int DEF_TYPE_INDEX = 42;

    private static String findingsIndexName() {
        return IndexNaming.indexNameForShortName("findings");
    }

    private void prepareTestEnvironment() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        OpenSearchClient client = OpenSearchReachable.getClient();
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(findingsIndexName()).build());
        } catch (IOException | RuntimeException e) {
            // Index may not exist; ignore so each test starts with a clean slate
        }
    }

    private void cleanupAfterTest() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
        OpenSearchClient client = OpenSearchReachable.getClient();
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(findingsIndexName()).build());
        } catch (IOException | RuntimeException e) {
            Logger.logError("[FindingsIndexReporterIT] Failed to delete index during cleanup: " + findingsIndexName(), e);
        }
    }

    @Test
    void pushSnapshotNow_indexesDocument_withExpectedShapeAndContent() throws InterruptedException {
        prepareTestEnvironment();
        try {
            createFindingsIndex();
            setRuntimeConfigForFindingsExport();
            setMockMontoyaApiWithOneIssue();

            List<String> infoLines = new ArrayList<>();
            Logger.LogListener logListener = (level, message) -> {
                if ("INFO".equals(level)) {
                    infoLines.add(message);
                }
            };
            Logger.registerListener(logListener);
            try {
                FindingsIndexReporter.start();
                FindingsIndexReporter.pushSnapshotNow();
                awaitInfoLog(infoLines, "[StartupExport] Findings: exporting backlog: 1 issue(s).");
                awaitInfoLogPrefix(infoLines, "[SnapshotExport] Findings: snapshot complete: captured=");
                awaitInfoLogPrefix(infoLines, "[SnapshotExport] Findings: backlog filters: seen=");
            } finally {
                Logger.unregisterListener(logListener);
            }

            Map<String, Object> doc = awaitFirstDocument();
            assertThat(doc).isNotNull();
            assertThat(doc).containsKey("burp");
            assertThat(doc).containsKey("issue");
            assertThat(doc).containsKey("target");
            assertThat(doc).doesNotContainKey("requests_responses");
            assertThat(doc).doesNotContainKey("request_responses_missing");
            assertThat(doc).containsKey("meta");
            assertThat(doc).doesNotContainKeys(
                    "name",
                    "severity",
                    "confidence",
                    "host",
                    "port",
                    "protocol_transport",
                    "protocol_application",
                    "protocol_sub",
                    "url",
                    "param",
                    "description",
                    "remediation_detail",
                    "issue_type_id",
                    "typical_severity",
                    "background",
                    "remediation_background");

            Map<String, Object> burp = asObjectMap(doc.get("burp"));
            assertThat(burp).isNotNull();
            assertThat(burp.get("is_in_scope")).isEqualTo(true);
            assertThat(burp.get("reporting_tool")).isEqualTo("Scanner");

            Map<String, Object> issue = asObjectMap(doc.get("issue"));
            assertThat(issue).isNotNull();
            assertThat(issue.get("name")).isEqualTo(ISSUE_NAME);
            assertThat(issue.get("severity")).isEqualTo(AuditIssueSeverity.HIGH.name());
            assertThat(issue.get("confidence")).isEqualTo(AuditIssueConfidence.CERTAIN.name());
            assertThat(issue.get("description")).isEqualTo(ISSUE_DETAIL);
            assertThat(issue.get("type_id")).isEqualTo(DEF_TYPE_INDEX);
            assertThat(issue.get("typical_severity")).isEqualTo(AuditIssueSeverity.HIGH.name());
            assertThat(issue.get("background")).isEqualTo(DEF_BACKGROUND);
            Map<String, Object> remediation = asObjectMap(issue.get("remediation"));
            assertThat(remediation).isNotNull();
            assertThat(remediation.get("detail")).isEqualTo(ISSUE_REMEDIATION);
            assertThat(remediation.get("background")).isEqualTo(DEF_REMEDIATION);

            Map<String, Object> target = asObjectMap(doc.get("target"));
            assertThat(target).isNotNull();
            assertThat(target.get("host")).isEqualTo(ISSUE_HOST);
            assertThat(target.get("port")).isEqualTo(ISSUE_PORT);
            assertThat(target.get("url")).isEqualTo(ISSUE_BASE_URL);
            Map<String, Object> targetProtocol = asObjectMap(target.get("protocol"));
            assertThat(targetProtocol).isNotNull();
            assertThat(targetProtocol.get("scheme")).isEqualTo("https");

            Map<String, Object> meta = asObjectMap(doc.get("meta"));
            assertThat(meta).isNotNull();
            assertThat(meta)
                    .containsKey("schema_version")
                    .containsKey("extension_version")
                    .containsKey("indexed_at");
        } finally {
            cleanupAfterTest();
        }
    }

    @Test
    void pushSnapshotNow_withOneRequestResponse_indexesRequestResponsesArrayWithFullShape() {
        prepareTestEnvironment();
        try {
            createFindingsIndex();
            setRuntimeConfigForFindingsExport();
            setMockMontoyaApiWithOneIssueWithRequestResponse();

            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            Map<String, Object> doc = awaitFirstDocument();
            assertThat(doc).isNotNull().containsKey("requests_responses");
            assertThat(doc).doesNotContainKey("request_responses_missing");

            List<?> requestResponses = asObjectList(doc.get("requests_responses"));
            assertThat(requestResponses).hasSize(1);
            Map<String, Object> pair = asObjectMap(requestResponses.get(0));
            assertThat(pair).isNotNull();
            assertThat(pair).containsKey("burp").containsKey("request").containsKey("response");

            Map<String, Object> req = asObjectMap(pair.get("request"));
            assertThat(req).isNotNull();
            assertThat(req).containsKeys("url", "port", "method", "path", "protocol", "header", "body");
            assertThat(req).doesNotContainKey("parameters");
            Map<String, Object> reqBody = asObjectMap(req.get("body"));
            assertThat(reqBody).isNotNull();
            assertThat(reqBody).containsKeys("length", "offset");
            assertThat(reqBody).doesNotContainKey("markers");
            assertThat(req.get("method")).isEqualTo("POST");

            Map<String, Object> resp = asObjectMap(pair.get("response"));
            assertThat(resp).isNotNull();
            assertThat(resp).containsKeys("status", "protocol", "header", "body");
            Map<String, Object> respBody = asObjectMap(resp.get("body"));
            assertThat(respBody).isNotNull();
            assertThat(respBody).containsKeys("length", "offset");
            assertThat(respBody).doesNotContainKey("markers");
            Map<String, Object> status = asObjectMap(resp.get("status"));
            assertThat(status).isNotNull();
            assertThat(status.get("code")).isEqualTo(200);
        } finally {
            cleanupAfterTest();
        }
    }

    @Test
    void pushSnapshotNow_withTwoRequestResponsePairs_indexesBothInRequestResponsesArray() {
        prepareTestEnvironment();
        try {
            createFindingsIndex();
            setRuntimeConfigForFindingsExport();
            setMockMontoyaApiWithOneIssueWithTwoRequestResponsePairs();

            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            Map<String, Object> doc = awaitFirstDocument();
            assertThat(doc).isNotNull().containsKey("requests_responses");
            assertThat(doc).doesNotContainKey("request_responses_missing");

            List<?> requestResponses = asObjectList(doc.get("requests_responses"));
            assertThat(requestResponses).hasSize(2);
            Map<String, Object> pair0 = asObjectMap(requestResponses.get(0));
            Map<String, Object> pair1 = asObjectMap(requestResponses.get(1));
            Map<String, Object> req0 = pair0 == null ? null : asObjectMap(pair0.get("request"));
            Map<String, Object> req1 = pair1 == null ? null : asObjectMap(pair1.get("request"));
            assertThat(req0).isNotNull();
            assertThat(req1).isNotNull();
            Map<String, Object> req0Checked = Objects.requireNonNull(req0);
            Map<String, Object> req1Checked = Objects.requireNonNull(req1);
            assertThat(req0Checked.get("method")).isEqualTo("GET");
            assertThat(req1Checked.get("method")).isEqualTo("POST");
        } finally {
            cleanupAfterTest();
        }
    }

    @Test
    void pushSnapshotNow_withRequestResponseWithNoResponse_usesEmptyResponseDoc() {
        prepareTestEnvironment();
        try {
            createFindingsIndex();
            setRuntimeConfigForFindingsExport();
            setMockMontoyaApiWithOneIssueWithRequestResponseNoResponse();

            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            // Wait for this test's document (path /no-response, empty response shape): scheduler is shared, so first doc may be from another test
            Map<String, Object> doc = awaitDocumentMatching(d -> {
                List<?> rr = asObjectList(d.get("requests_responses"));
                if (rr == null || rr.size() != 1) return false;
                Map<String, Object> pair = asObjectMap(rr.get(0));
                if (pair == null) return false;
                Map<String, Object> req = asObjectMap(pair.get("request"));
                if (req == null) return false;
                Map<String, Object> path = asObjectMap(req.get("path"));
                Map<String, Object> resp = asObjectMap(pair.get("response"));
                Map<String, Object> respBody = resp == null ? null : asObjectMap(resp.get("body"));
                return path != null
                        && "/no-response".equals(path.get("with_query"))
                        && respBody != null
                        && Integer.valueOf(0).equals(respBody.get("length"));
            });
            assertThat(doc).doesNotContainKey("request_responses_missing");
            List<?> requestResponses = asObjectList(doc.get("requests_responses"));
            assertThat(requestResponses).as("requests_responses").hasSize(1);
            Map<String, Object> firstPair = asObjectMap(requestResponses.get(0));
            assertThat(firstPair).isNotNull();
            Map<String, Object> firstPairChecked = Objects.requireNonNull(firstPair);
            assertThat(firstPairChecked).containsKey("response");
            Map<String, Object> resp = asObjectMap(firstPairChecked.get("response"));
            assertThat(resp).isNotNull();
            Map<String, Object> respChecked = Objects.requireNonNull(resp);
            Map<String, Object> respBody = asObjectMap(respChecked.get("body"));
            assertThat(respBody).isNotNull();
            assertThat(respBody.get("length")).isEqualTo(0);
            Map<String, Object> status = asObjectMap(respChecked.get("status"));
            assertThat(status == null || !status.containsKey("code") || status.get("code") == null).isTrue();
        } finally {
            cleanupAfterTest();
        }
    }

    private void createFindingsIndex() {
        List<OpenSearchSink.IndexResult> results = OpenSearchReachable.createSelectedIndexes(List.of("findings"));
        assertThat(results).isNotEmpty();
        boolean findingsCreated = results.stream()
                .anyMatch(r -> r.shortName().equals("findings") && (r.status() == OpenSearchSink.IndexResult.Status.CREATED || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(findingsCreated).as("findings index created or exists").isTrue();
    }

    private void setRuntimeConfigForFindingsExport() {
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, BASE_URL,
                config.username(), config.password(), false);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
    }

    private void setMockMontoyaApiWithOneIssue() {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService httpService = mock(HttpService.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.issues()).thenReturn(List.of(issue));

        when(issue.name()).thenReturn(ISSUE_NAME);
        when(issue.baseUrl()).thenReturn(ISSUE_BASE_URL);
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.httpService()).thenReturn(httpService);
        when(issue.detail()).thenReturn(ISSUE_DETAIL);
        when(issue.remediation()).thenReturn(ISSUE_REMEDIATION);
        when(issue.definition()).thenReturn(definition);
        when(issue.requestResponses()).thenReturn(List.of());

        when(httpService.host()).thenReturn(ISSUE_HOST);
        when(httpService.port()).thenReturn(ISSUE_PORT);
        when(httpService.secure()).thenReturn(true);

        when(definition.typeIndex()).thenReturn(DEF_TYPE_INDEX);
        when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.HIGH);
        when(definition.background()).thenReturn(DEF_BACKGROUND);
        when(definition.remediation()).thenReturn(DEF_REMEDIATION);

        MontoyaApiProvider.set(api);
    }

    private void setMockMontoyaApiWithOneIssueWithRequestResponse() {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService httpService = mock(HttpService.class);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpResponse resp = mock(HttpResponse.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.issues()).thenReturn(List.of(issue));

        when(issue.name()).thenReturn(ISSUE_NAME);
        when(issue.baseUrl()).thenReturn(ISSUE_BASE_URL);
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.httpService()).thenReturn(httpService);
        when(issue.detail()).thenReturn(ISSUE_DETAIL);
        when(issue.remediation()).thenReturn(ISSUE_REMEDIATION);
        when(issue.definition()).thenReturn(definition);
        when(issue.requestResponses()).thenReturn(List.of(rr));

        when(httpService.host()).thenReturn(ISSUE_HOST);
        when(httpService.port()).thenReturn(ISSUE_PORT);
        when(httpService.secure()).thenReturn(true);

        when(definition.typeIndex()).thenReturn(DEF_TYPE_INDEX);
        when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.HIGH);
        when(definition.background()).thenReturn(DEF_BACKGROUND);
        when(definition.remediation()).thenReturn(DEF_REMEDIATION);

        mockRequestResponsePair(rr, req, resp, "POST", "/api");

        MontoyaApiProvider.set(api);
    }

    private void setMockMontoyaApiWithOneIssueWithTwoRequestResponsePairs() {
        HttpRequestResponse rr1 = mock(HttpRequestResponse.class);
        HttpRequest req1 = mock(HttpRequest.class);
        HttpResponse resp1 = mock(HttpResponse.class);
        HttpRequestResponse rr2 = mock(HttpRequestResponse.class);
        HttpRequest req2 = mock(HttpRequest.class);
        HttpResponse resp2 = mock(HttpResponse.class);

        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService httpService = mock(HttpService.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.issues()).thenReturn(List.of(issue));

        when(issue.name()).thenReturn(ISSUE_NAME);
        when(issue.baseUrl()).thenReturn(ISSUE_BASE_URL);
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.httpService()).thenReturn(httpService);
        when(issue.detail()).thenReturn(ISSUE_DETAIL);
        when(issue.remediation()).thenReturn(ISSUE_REMEDIATION);
        when(issue.definition()).thenReturn(definition);
        when(issue.requestResponses()).thenReturn(List.of(rr1, rr2));

        when(httpService.host()).thenReturn(ISSUE_HOST);
        when(httpService.port()).thenReturn(ISSUE_PORT);
        when(httpService.secure()).thenReturn(true);

        when(definition.typeIndex()).thenReturn(DEF_TYPE_INDEX);
        when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.HIGH);
        when(definition.background()).thenReturn(DEF_BACKGROUND);
        when(definition.remediation()).thenReturn(DEF_REMEDIATION);

        mockRequestResponsePair(rr1, req1, resp1, "GET", "/first");
        mockRequestResponsePair(rr2, req2, resp2, "POST", "/second");

        MontoyaApiProvider.set(api);
    }

    private void setMockMontoyaApiWithOneIssueWithRequestResponseNoResponse() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);

        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService httpService = mock(HttpService.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope(anyString())).thenReturn(true);
        doReturn(List.of(issue)).when(siteMap).issues();

        when(issue.name()).thenReturn(ISSUE_NAME);
        when(issue.baseUrl()).thenReturn(ISSUE_BASE_URL);
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.httpService()).thenReturn(httpService);
        when(issue.detail()).thenReturn(ISSUE_DETAIL);
        when(issue.remediation()).thenReturn(ISSUE_REMEDIATION);
        when(issue.definition()).thenReturn(definition);
        doReturn(List.of(rr)).when(issue).requestResponses();

        when(httpService.host()).thenReturn(ISSUE_HOST);
        when(httpService.port()).thenReturn(ISSUE_PORT);
        when(httpService.secure()).thenReturn(true);

        when(definition.typeIndex()).thenReturn(DEF_TYPE_INDEX);
        when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.HIGH);
        when(definition.background()).thenReturn(DEF_BACKGROUND);
        when(definition.remediation()).thenReturn(DEF_REMEDIATION);

        doReturn(req).when(rr).request();
        when(rr.hasResponse()).thenReturn(false);
        when(rr.response()).thenReturn(null);

        when(req.method()).thenReturn("GET");
        when(req.path()).thenReturn("/no-response");
        when(req.pathWithoutQuery()).thenReturn("/no-response");
        when(req.query()).thenReturn("");
        when(req.fileExtension()).thenReturn("");
        when(req.httpVersion()).thenReturn("HTTP/1.1");
        when(req.headers()).thenReturn(List.of());
        when(req.parameters()).thenReturn(List.of());
        when(req.body()).thenReturn(null);
        when(req.bodyOffset()).thenReturn(0);
        when(req.markers()).thenReturn(List.of());
        when(req.contentType()).thenReturn(ContentType.NONE);

        MontoyaApiProvider.set(api);
    }

    private static void mockRequestResponsePair(HttpRequestResponse rr, HttpRequest req, HttpResponse resp,
                                                String method, String path) {
        when(rr.request()).thenReturn(req);
        when(rr.hasResponse()).thenReturn(true);
        when(rr.response()).thenReturn(resp);

        when(req.method()).thenReturn(method);
        when(req.path()).thenReturn(path);
        when(req.pathWithoutQuery()).thenReturn(path);
        when(req.query()).thenReturn("");
        when(req.fileExtension()).thenReturn("");
        when(req.httpVersion()).thenReturn("HTTP/1.1");
        when(req.headers()).thenReturn(List.of());
        when(req.parameters()).thenReturn(List.of());
        when(req.body()).thenReturn(null);
        when(req.bodyOffset()).thenReturn(0);
        when(req.markers()).thenReturn(List.of());
        when(req.contentType()).thenReturn(ContentType.NONE);

        when(resp.statusCode()).thenReturn((short) 200);
        when(resp.reasonPhrase()).thenReturn("OK");
        when(resp.httpVersion()).thenReturn("HTTP/1.1");
        when(resp.headers()).thenReturn(List.of());
        when(resp.cookies()).thenReturn(List.of());
        when(resp.mimeType()).thenReturn(MimeType.HTML);
        when(resp.statedMimeType()).thenReturn(MimeType.HTML);
        when(resp.inferredMimeType()).thenReturn(MimeType.HTML);
        when(resp.body()).thenReturn(null);
        when(resp.bodyOffset()).thenReturn(0);
        when(resp.markers()).thenReturn(List.of());
    }

    private Map<String, Object> awaitFirstDocument() {
        return awaitDocumentMatching(d -> true);
    }

    /** Polls until a document matching the predicate appears (avoids taking a doc from another test's late task). */
    private Map<String, Object> awaitDocumentMatching(Predicate<Map<String, Object>> predicate) {
        OpenSearchClient client = OpenSearchReachable.getClient();
        SearchRequest req = new SearchRequest.Builder()
                .index(findingsIndexName())
                .size(20)
                .build();
        int maxAttempts = 120;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(findingsIndexName()).build());
            } catch (IOException | RuntimeException ignored) {
                // best-effort refresh
            }
            try {
                SearchResponse<?> resp = client.search(req, Map.class);
                for (var hit : resp.hits().hits()) {
                    Map<String, Object> source = asObjectMap(hit.source());
                    if (source != null && predicate.test(source)) {
                        return source;
                    }
                }
            } catch (IOException | RuntimeException e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            if (i < maxAttempts - 1) {
                LockSupport.parkNanos(300_000_000L);
                if (Thread.currentThread().isInterrupted()) {
                    throw new AssertionError("Interrupted while awaiting document");
                }
            }
        }
        String diag = buildDocumentMatchDiagnostic(client);
        throw new AssertionError("no matching document indexed (after " + maxAttempts + " attempts). " + diag);
    }

    private String buildDocumentMatchDiagnostic(OpenSearchClient client) {
        try {
            client.indices().refresh(new RefreshRequest.Builder().index(findingsIndexName()).build());
        } catch (IOException | RuntimeException ignored) { }
        try {
            SearchResponse<?> resp = client.search(
                    new SearchRequest.Builder().index(findingsIndexName()).size(20).build(),
                    Map.class);
            var hits = resp.hits().hits();
            if (hits.isEmpty()) return "Index had 0 documents.";
            StringBuilder sb = new StringBuilder("Index had ").append(hits.size()).append(" doc(s): ");
            for (int j = 0; j < hits.size(); j++) {
                Map<String, Object> src = asObjectMap(hits.get(j).source());
                if (j > 0) sb.append("; ");
                if (src == null) {
                    sb.append("doc").append(j).append(" source=null");
                    continue;
                }
                List<?> rr = asObjectList(src.get("requests_responses"));
                sb.append("doc").append(j).append(" requests_responses.size=").append(rr != null ? rr.size() : "null");
                if (rr != null && !rr.isEmpty() && rr.get(0) instanceof Map) {
                    Map<String, Object> pair = asObjectMap(rr.get(0));
                    if (pair == null) {
                        continue;
                    }
                    Map<String, Object> req = asObjectMap(pair.get("request"));
                    sb.append(" first.path=").append(req != null ? req.get("path") : "n/a");
                    Map<String, Object> respDoc = asObjectMap(pair.get("response"));
                    Map<String, Object> status = respDoc == null ? null : asObjectMap(respDoc.get("status"));
                    sb.append(" first.response.status.code=").append(status != null ? status.get("code") : "n/a");
                }
            }
            return sb.toString();
        } catch (IOException | RuntimeException e) {
            return "Diagnostic search failed: " + e.getMessage();
        }
    }

    private static Map<String, Object> asObjectMap(Object value) {
        if (!(value instanceof Map<?, ?> raw)) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (entry.getKey() instanceof String key) {
                out.put(key, entry.getValue());
            }
        }
        return out;
    }

    private static List<?> asObjectList(Object value) {
        if (value instanceof List<?> list) {
            return list;
        }
        return null;
    }

    private static void awaitInfoLog(List<String> infoLines, String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (System.nanoTime() < deadline) {
            if (infoLines.contains(expected)) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(infoLines).contains(expected);
    }

    private static void awaitInfoLogPrefix(List<String> infoLines, String prefix) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (System.nanoTime() < deadline) {
            if (infoLines.stream().anyMatch(line -> line.startsWith(prefix))) {
                return;
            }
            Thread.sleep(20);
        }
        assertThat(infoLines).anyMatch(line -> line.startsWith(prefix));
    }
}
