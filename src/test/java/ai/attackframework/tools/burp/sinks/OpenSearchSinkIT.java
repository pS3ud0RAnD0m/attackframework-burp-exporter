package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Integration tests for index lifecycle using OpenSearchSink against a live test cluster.
 * Tests create, existence reporting, deletion, and re-creation of the standard indices.
 * Run via {@link OpenSearchIntegrationSuite}; tag "integration" is on the suite.
 */
class OpenSearchSinkIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = "http://opensearch.url:9200";

    /**
     * Verifies full lifecycle for the standard index set using the sink:
     * 1) Create or detect existing indices
     * 2) Delete all reported indices
     * 3) Re-create indices and verify creation status
     * 4) Validate full index naming
     */
    @Test
    void create_delete_recreate_standardIndices_viaSink() throws IOException {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<String> sources = List.of("settings", "sitemap", "findings", "traffic", "tool");

        // Pass 1: create or report existing
        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, sources);

        EnumSet<IndexResult.Status> allowed = EnumSet.of(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        assertThat(first)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isIn(allowed));

        // Validate full index naming
        for (IndexResult r : first) {
            String expectedFull = r.shortName().equals("tool")
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + r.shortName();
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Delete reported indices (best-effort cleanup of dev cluster)
        List<String> fullNames = first.stream().map(IndexResult::fullName).toList();
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (String index : fullNames) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(index).build());
            } catch (Exception e) {
                // Best-effort cleanup: index may already be missing or the dev cluster may have been reset.
                // Log instead of failing the lifecycle assertions above.
                Logger.logError("[OpenSearchSinkIT] Failed to delete index during test cleanup: " + index, e);
            }
        }

        // Verify deletion
        for (String index : fullNames) {
            boolean exists = client.indices().exists(b -> b.index(index)).value();
            assertThat(exists).isFalse();
        }

        // Pass 2: re-create and verify CREATED status
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, sources);
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));

        // Short names check
        Set<String> seenShort = second.stream().map(IndexResult::shortName).collect(Collectors.toSet());
        assertThat(seenShort).contains("tool", "settings", "sitemap", "findings", "traffic");
    }

    /**
     * Verifies lifecycle for a single source ("traffic") using the sink:
     * create (or exist), delete, re-create, and full name validation.
     */
    @Test
    void create_delete_recreate_singleSource_traffic_viaSink() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("traffic", "tool"));
        assertThat(first).isNotEmpty();

        // Validate expected short names and full names
        for (IndexResult r : first) {
            String expectedFull = r.shortName().equals("tool")
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + r.shortName();
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Delete both indices reported (best-effort cleanup of dev cluster)
        OpenSearchClient client2 = OpenSearchConnector.getClient(BASE_URL);
        for (IndexResult r : first) {
            try {
                client2.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception e) {
                Logger.logError("[OpenSearchSinkIT] Failed to delete index during single-source test cleanup: " + r.fullName(), e);
            }
        }

        // Re-create and verify CREATED status
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("traffic", "tool"));
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));
    }
}
