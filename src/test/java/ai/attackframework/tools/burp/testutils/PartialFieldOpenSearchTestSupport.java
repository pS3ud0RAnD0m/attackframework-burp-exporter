package ai.attackframework.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Shared helpers for integration tests that index partially field-filtered documents
 * against the configured OpenSearch test cluster.
 */
public final class PartialFieldOpenSearchTestSupport {

    private static final ObjectMapper JSON = new ObjectMapper();

    private PartialFieldOpenSearchTestSupport() {}

    /** Configured cluster base URL ({@link OpenSearchTestConfig#get()}). */
    public static String baseUrl() {
        return OpenSearchTestConfig.get().baseUrl();
    }

    /** Builds {@link ConfigState.Sinks} aimed at {@link #baseUrl()} with test-cluster credentials. */
    public static ConfigState.Sinks openSearchSinks() {
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        return new ConfigState.Sinks(false, "", true, config.baseUrl(), config.username(), config.password(), false);
    }

    /**
     * Creates the OpenSearch index for {@code indexShortName} using mapping resources.
     *
     * @param indexShortName index short name (for example {@code "traffic"})
     */
    public static void createIndex(String indexShortName) {
        List<OpenSearchSink.IndexResult> results =
                OpenSearchReachable.createSelectedIndexes(List.of(indexShortName));
        assertThat(results).isNotEmpty();
        boolean created = results.stream()
                .anyMatch(r -> r.shortName().equals(indexShortName)
                        && (r.status() == OpenSearchSink.IndexResult.Status.CREATED
                                || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(created).as(indexShortName + " index created or exists").isTrue();
    }

    /**
     * Deletes the test index for {@code indexShortName}; ignores missing-index errors.
     *
     * @param indexShortName index short name
     */
    public static void deleteIndex(String indexShortName) {
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        try {
            OpenSearchReachable.getClient().indices().delete(
                    new DeleteIndexRequest.Builder().index(indexName).build());
        } catch (IOException | RuntimeException ignored) {
            // Cleanup is best-effort between integration tests.
        }
    }

    /**
     * Applies {@code runtimeState}, pushes one filtered document, and returns the prepared export.
     *
     * @param indexShortName index short name
     * @param built unfiltered document map (filtered during push)
     * @param runtimeState export configuration including enabled field paths
     * @return prepared export identity for search assertions
     */
    public static PreparedExportDocument pushOneDocument(
            String indexShortName,
            Map<String, Object> built,
            ConfigState.State runtimeState) {
        RuntimeConfig.updateState(runtimeState);
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        PreparedExportDocument prepared =
                ExportDocumentIdentity.prepare(indexName, indexShortName, built);
        int pushed = OpenSearchClientWrapper.pushBulk(
                baseUrl(), indexName, indexShortName, List.of(built));
        assertThat(pushed).as("bulk push to " + indexShortName).isEqualTo(1);
        return prepared;
    }

    /**
     * Polls OpenSearch until the document with {@code exportId} is visible, or fails the test.
     *
     * @param indexShortName index short name
     * @param exportId {@code meta.export_id} value
     * @return stored document source map
     */
    public static Map<String, Object> awaitDocumentByExportId(String indexShortName, String exportId) {
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        OpenSearchClient client = OpenSearchReachable.getClient();
        SearchRequest request = new SearchRequest.Builder()
                .index(indexName)
                .size(5)
                .build();
        for (int attempt = 0; attempt < 80; attempt++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(indexName).build());
            } catch (IOException | RuntimeException ignored) {
                // Refresh before search is best-effort; polling retries on the next attempt.
            }
            try {
                SearchResponse<JsonNode> response = client.search(request, JsonNode.class);
                for (var hit : response.hits().hits()) {
                    JsonNode sourceNode = hit.source();
                    if (sourceNode == null) {
                        continue;
                    }
                    Map<String, Object> source =
                            JSON.convertValue(sourceNode, new TypeReference<Map<String, Object>>() { });
                    Map<?, ?> meta = nestedMap(source, "meta");
                    if (exportId.equals(meta.get("export_id"))) {
                        return source;
                    }
                }
            } catch (IOException | RuntimeException e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(250));
        }
        throw new AssertionError("No document indexed for export_id=" + exportId + " in " + indexShortName);
    }

    /** Asserts {@code key} is a nested map and returns it. */
    public static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }
}
