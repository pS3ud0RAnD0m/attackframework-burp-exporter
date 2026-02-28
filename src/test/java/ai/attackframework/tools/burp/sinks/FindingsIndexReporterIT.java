package ai.attackframework.tools.burp.sinks;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
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

    private static final String BASE_URL = "http://opensearch.url:9200";
    private static final String FINDINGS_INDEX = IndexNaming.INDEX_PREFIX + "-findings";

    private static final String ISSUE_NAME = "SQL injection";
    private static final String ISSUE_BASE_URL = "https://example.com/page";
    private static final String ISSUE_HOST = "example.com";
    private static final int ISSUE_PORT = 443;
    private static final String ISSUE_DETAIL = "Parameter id is vulnerable.";
    private static final String ISSUE_REMEDIATION = "Use parameterized queries.";
    private static final String DEF_BACKGROUND = "SQL injection allows...";
    private static final String DEF_REMEDIATION = "Use prepared statements.";
    private static final int DEF_TYPE_INDEX = 42;

    @BeforeEach
    void assumeOpenSearchReachable() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");
    }

    @AfterEach
    void cleanup() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(FINDINGS_INDEX).build());
        } catch (Exception e) {
            Logger.logError("[FindingsIndexReporterIT] Failed to delete index during cleanup: " + FINDINGS_INDEX, e);
        }
    }

    @Test
    void pushSnapshotNow_indexesDocument_withExpectedShapeAndContent() {
        createFindingsIndex();
        setRuntimeConfigForFindingsExport();
        setMockMontoyaApiWithOneIssue();

        FindingsIndexReporter.start();
        FindingsIndexReporter.pushSnapshotNow();

        Map<String, Object> doc = awaitFirstDocument();
        assertThat(doc).isNotNull();
        assertThat(doc).containsKey("name");
        assertThat(doc).containsKey("severity");
        assertThat(doc).containsKey("confidence");
        assertThat(doc).containsKey("host");
        assertThat(doc).containsKey("port");
        assertThat(doc).containsKey("protocol_transport");
        assertThat(doc).containsKey("url");
        assertThat(doc).containsKey("request_responses");
        assertThat(doc).containsKey("request_responses_missing");
        assertThat(doc).containsKey("document_meta");
        assertThat(doc).containsKey("description");
        assertThat(doc).containsKey("remediation_detail");
        assertThat(doc).containsKey("issue_type_id");
        assertThat(doc).containsKey("typical_severity");
        assertThat(doc).containsKey("background");
        assertThat(doc).containsKey("remediation_background");

        assertThat(doc.get("name")).isEqualTo(ISSUE_NAME);
        assertThat(doc.get("severity")).isEqualTo(AuditIssueSeverity.HIGH.name());
        assertThat(doc.get("confidence")).isEqualTo(AuditIssueConfidence.CERTAIN.name());
        assertThat(doc.get("host")).isEqualTo(ISSUE_HOST);
        assertThat(doc.get("port")).isEqualTo(ISSUE_PORT);
        assertThat(doc.get("protocol_transport")).isEqualTo("https");
        assertThat(doc.get("url")).isEqualTo(ISSUE_BASE_URL);
        assertThat((List<?>) doc.get("request_responses")).isEmpty();
        assertThat(doc.get("request_responses_missing")).isEqualTo(true);
        assertThat(doc.get("description")).isEqualTo(ISSUE_DETAIL);
        assertThat(doc.get("remediation_detail")).isEqualTo(ISSUE_REMEDIATION);
        assertThat(doc.get("issue_type_id")).isEqualTo(DEF_TYPE_INDEX);
        assertThat(doc.get("typical_severity")).isEqualTo(AuditIssueSeverity.HIGH.name());
        assertThat(doc.get("background")).isEqualTo(DEF_BACKGROUND);
        assertThat(doc.get("remediation_background")).isEqualTo(DEF_REMEDIATION);

        @SuppressWarnings("unchecked")
        Map<String, Object> documentMeta = (Map<String, Object>) doc.get("document_meta");
        assertThat(documentMeta).isNotNull()
                .containsKey("schema_version")
                .containsKey("extension_version")
                .containsKey("indexed_at");
    }

    @Test
    void pushSnapshotNow_withOneRequestResponse_indexesRequestResponsesArrayWithFullShape() {
        createFindingsIndex();
        setRuntimeConfigForFindingsExport();
        setMockMontoyaApiWithOneIssueWithRequestResponse();

        FindingsIndexReporter.start();
        FindingsIndexReporter.pushSnapshotNow();

        Map<String, Object> doc = awaitFirstDocument();
        assertThat(doc).isNotNull().containsKey("request_responses");
        assertThat(doc.get("request_responses_missing")).isEqualTo(false);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> requestResponses = (List<Map<String, Object>>) doc.get("request_responses");
        assertThat(requestResponses).hasSize(1);
        Map<String, Object> pair = requestResponses.get(0);
        assertThat(pair).containsKey("request").containsKey("response");

        @SuppressWarnings("unchecked")
        Map<String, Object> req = (Map<String, Object>) pair.get("request");
        assertThat(req).containsKeys("method", "path", "headers", "parameters", "markers", "body_length");
        assertThat(req.get("method")).isEqualTo("POST");

        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) pair.get("response");
        assertThat(resp).containsKeys("status", "reason_phrase", "headers", "markers", "body_length");
        assertThat(resp.get("status")).isEqualTo(200);
    }

    @Test
    void pushSnapshotNow_withTwoRequestResponsePairs_indexesBothInRequestResponsesArray() {
        createFindingsIndex();
        setRuntimeConfigForFindingsExport();
        setMockMontoyaApiWithOneIssueWithTwoRequestResponsePairs();

        FindingsIndexReporter.start();
        FindingsIndexReporter.pushSnapshotNow();

        Map<String, Object> doc = awaitFirstDocument();
        assertThat(doc).isNotNull().containsKey("request_responses");
        assertThat(doc.get("request_responses_missing")).isEqualTo(false);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> requestResponses = (List<Map<String, Object>>) doc.get("request_responses");
        assertThat(requestResponses).hasSize(2);
        assertThat(((Map<String, Object>) requestResponses.get(0).get("request")).get("method")).isEqualTo("GET");
        assertThat(((Map<String, Object>) requestResponses.get(1).get("request")).get("method")).isEqualTo("POST");
    }

    @Test
    void pushSnapshotNow_withRequestResponseWithNoResponse_usesEmptyResponseDoc() {
        createFindingsIndex();
        setRuntimeConfigForFindingsExport();
        setMockMontoyaApiWithOneIssueWithRequestResponseNoResponse();

        FindingsIndexReporter.start();
        FindingsIndexReporter.pushSnapshotNow();

        Map<String, Object> doc = awaitFirstDocument();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> requestResponses = (List<Map<String, Object>>) doc.get("request_responses");
        assertThat(requestResponses).hasSize(1);
        Map<String, Object> resp = (Map<String, Object>) requestResponses.get(0).get("response");
        assertThat(resp.get("status")).isEqualTo(0);
        assertThat((List<?>) resp.get("markers")).isEmpty();
        assertThat((List<?>) resp.get("headers")).isEmpty();
    }

    private void createFindingsIndex() {
        List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("findings"));
        assertThat(results).isNotEmpty();
        boolean findingsCreated = results.stream()
                .anyMatch(r -> r.shortName().equals("findings") && (r.status() == OpenSearchSink.IndexResult.Status.CREATED || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(findingsCreated).as("findings index created or exists").isTrue();
    }

    private void setRuntimeConfigForFindingsExport() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, BASE_URL);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks);
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

        when(rr.request()).thenReturn(req);
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

    @SuppressWarnings("unchecked")
    private Map<String, Object> awaitFirstDocument() {
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        SearchRequest req = new SearchRequest.Builder()
                .index(FINDINGS_INDEX)
                .size(1)
                .build();
        // Allow time for retry-coordinator drain thread (runs every 5s) when first push is queued
        int maxAttempts = 40;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(FINDINGS_INDEX).build());
            } catch (Exception ignored) {
                // best-effort refresh
            }
            try {
                SearchResponse<Map<String, Object>> resp = client.search(req, (Class<Map<String, Object>>) (Class<?>) Map.class);
                List<?> hits = resp.hits().hits();
                if (!hits.isEmpty()) {
                    return (Map<String, Object>) resp.hits().hits().get(0).source();
                }
            } catch (Exception e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            if (i < maxAttempts - 1) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("Interrupted while awaiting document", e);
                }
            }
        }
        throw new AssertionError("at least one document indexed (after " + maxAttempts + " attempts)");
    }
}
