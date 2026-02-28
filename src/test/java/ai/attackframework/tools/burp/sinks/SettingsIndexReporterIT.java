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
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.project.Project;

/**
 * Integration test: {@link SettingsIndexReporter} pushes a document to the
 * settings index when export is running and Burp API is available. Uses the
 * real OpenSearch instance at {@value #BASE_URL}; mocks Burp's MontoyaApi to
 * supply project/user JSON and project id. Verifies document shape and content
 * after round-trip. Uses real OpenSearch at {@value #BASE_URL}; run with full
 * test task or exclude with {@code -PexcludeIntegration} to skip.
 */
@Tag("integration")
class SettingsIndexReporterIT {

    private static final String BASE_URL = "http://opensearch.url:9200";
    private static final String SETTINGS_INDEX = IndexNaming.INDEX_PREFIX + "-settings";

    private static final String PROJECT_JSON = "{\"project_options\":{\"test_key\":\"project_value\"}}";
    private static final String USER_JSON = "{\"user_options\":{\"test_key\":\"user_value\"}}";
    private static final String PROJECT_ID = "it-settings-project-id";

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
            client.indices().delete(new DeleteIndexRequest.Builder().index(SETTINGS_INDEX).build());
        } catch (Exception e) {
            Logger.logError("[SettingsIndexReporterIT] Failed to delete index during cleanup: " + SETTINGS_INDEX, e);
        }
    }

    @Test
    void pushSnapshotNow_indexesDocument_withExpectedShapeAndContent() {
        createSettingsIndex();
        setRuntimeConfigForSettingsExport();
        setMockMontoyaApi();

        SettingsIndexReporter.pushSnapshotNow();

        Map<String, Object> doc = awaitFirstDocument();
        assertThat(doc).isNotNull();
        assertThat(doc).containsKey("project_id");
        assertThat(doc).containsKey("settings_project");
        assertThat(doc).containsKey("settings_user");
        assertThat(doc).containsKey("document_meta");

        assertThat(doc.get("project_id")).isEqualTo(PROJECT_ID);

        @SuppressWarnings("unchecked")
        Map<String, Object> settingsProject = (Map<String, Object>) doc.get("settings_project");
        assertThat(settingsProject).isNotNull().containsEntry("project_options",
                Map.of("test_key", "project_value"));

        @SuppressWarnings("unchecked")
        Map<String, Object> settingsUser = (Map<String, Object>) doc.get("settings_user");
        assertThat(settingsUser).isNotNull().containsEntry("user_options",
                Map.of("test_key", "user_value"));

        @SuppressWarnings("unchecked")
        Map<String, Object> documentMeta = (Map<String, Object>) doc.get("document_meta");
        assertThat(documentMeta).isNotNull()
                .containsKey("schema_version")
                .containsKey("extension_version")
                .containsKey("indexed_at");
    }

    private void createSettingsIndex() {
        List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("settings"));
        assertThat(results).isNotEmpty();
        boolean settingsCreated = results.stream()
                .anyMatch(r -> r.shortName().equals("settings") && (r.status() == OpenSearchSink.IndexResult.Status.CREATED || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(settingsCreated).as("settings index created or exists").isTrue();
    }

    private void setRuntimeConfigForSettingsExport() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, BASE_URL);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
    }

    private void setMockMontoyaApi() {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Project project = mock(Project.class);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(api.project()).thenReturn(project);
        when(burpSuite.exportProjectOptionsAsJson()).thenReturn(PROJECT_JSON);
        when(burpSuite.exportUserOptionsAsJson()).thenReturn(USER_JSON);
        when(project.id()).thenReturn(PROJECT_ID);
        MontoyaApiProvider.set(api);
    }

    /**
     * Refreshes the settings index and searches until at least one document is
     * found or the retry limit is reached (handles refresh latency when cluster
     * is under load, e.g. in the integration suite).
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> awaitFirstDocument() {
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        SearchRequest req = new SearchRequest.Builder()
                .index(SETTINGS_INDEX)
                .size(1)
                .build();
        int maxAttempts = 5;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(SETTINGS_INDEX).build());
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
