package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.IndexNaming;

/**
 * Integration test: force fresh creation of all standard indices.
 * Deletes each index first, then recreates and asserts CREATED status.
 * Run via {@link OpenSearchIntegrationSuite}; tag "integration" is on the suite.
 */
class OpenSearchSinkFreshCreateIT {

    private static final List<String> SOURCES = List.of("tool", "settings", "sitemap", "findings", "traffic");

    private static final int WAIT_AFTER_DELETE_MS = 500;
    private static final int POLL_EXISTS_MAX_MS = 5_000;
    private static final int POLL_INTERVAL_MS = 100;

    @Test
    void deleteThenCreate_allStandardIndices_reportsCreated() throws InterruptedException, IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        OpenSearchClient client = OpenSearchReachable.getClient();

        // Delete all first (best effort)
        for (String s : SOURCES) {
            String fullName = IndexNaming.indexNameForShortName(s);
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(fullName).build());
            } catch (Exception ignored) {
                // Index may not exist yet; deletion is best-effort for a clean slate.
            }
        }

        // Wait for deletes to be visible so create sees indices as missing
        Thread.sleep(WAIT_AFTER_DELETE_MS);
        for (String s : SOURCES) {
            String fullName = IndexNaming.indexNameForShortName(s);
            long deadline = System.currentTimeMillis() + POLL_EXISTS_MAX_MS;
            while (client.indices().exists(b -> b.index(fullName)).value() && System.currentTimeMillis() < deadline) {
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }

        // Re-create each index and assert CREATED
        List<IndexResult> results = OpenSearchReachable.createSelectedIndexes(SOURCES);
        assertThat(results).isNotEmpty();

        for (IndexResult r : results) {
            String expectedFull = IndexNaming.indexNameForShortName(r.shortName());

            assertThat(r.fullName()).isEqualTo(expectedFull);
            assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED);
        }
    }
}
