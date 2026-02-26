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
        assertThat(doc).containsKey("request_responses_missing");
        assertThat(doc).containsKey("indexed_at");
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
                .containsKey("extension_version");
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

    @SuppressWarnings("unchecked")
    private Map<String, Object> awaitFirstDocument() {
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        SearchRequest req = new SearchRequest.Builder()
                .index(FINDINGS_INDEX)
                .size(1)
                .build();
        int maxAttempts = 5;
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
