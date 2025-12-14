package ai.attackframework.tools.burp.sinks;

import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Integration test: force fresh creation of all standard indices.
 * Deletes each index first, then recreates and asserts CREATED status.
 */
@Tag("integration")
class OpenSearchSinkFreshCreateIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    private static final List<String> SOURCES = List.of("tool", "settings", "sitemap", "findings", "traffic");

    @Test
    void deleteThenCreate_allStandardIndices_reportsCreated() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        // Delete all first (best effort)
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (String s : SOURCES) {
            String fullName = "tool".equals(s)
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + s;
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(fullName).build());
            } catch (Exception ignored) {
                // Index may not exist yet; deletion is best-effort for a clean slate.
            }
        }

        // Re-create each index and assert CREATED
        List<IndexResult> results = OpenSearchSink.createSelectedIndexes(BASE_URL, SOURCES);
        assertThat(results).isNotEmpty();

        for (IndexResult r : results) {
            String expectedFull = "tool".equals(r.shortName())
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + r.shortName();

            assertThat(r.fullName()).isEqualTo(expectedFull);
            assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED);
        }
    }
}
