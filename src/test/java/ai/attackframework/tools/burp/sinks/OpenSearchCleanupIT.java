package ai.attackframework.tools.burp.sinks;

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Runs last in {@link OpenSearchIntegrationSuite} and deletes the standard
 * OpenSearch indexes in @AfterAll so no indexes are left after the suite.
 * The suite engine does not run lifecycle on the suite class itself, so
 * cleanup must live in a real test class.
 */
class OpenSearchCleanupIT {

    private static final String BASE_URL = "http://opensearch.url:9200";
    private static final List<String> STANDARD_SHORT_NAMES =
            List.of("settings", "sitemap", "findings", "traffic", "tool");

    @Test
    void placeholder_soAfterAllRuns() {
        // No-op; ensures this class is executed so @AfterAll runs.
    }

    @AfterAll
    static void deleteCreatedIndices() {
        try {
            OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
            for (String s : STANDARD_SHORT_NAMES) {
                String fullName = "tool".equals(s)
                        ? IndexNaming.INDEX_PREFIX
                        : IndexNaming.INDEX_PREFIX + "-" + s;
                try {
                    client.indices().delete(new DeleteIndexRequest.Builder().index(fullName).build());
                } catch (Exception ignored) {
                    // Index may not exist or cluster unreachable; best-effort only.
                }
            }
        } catch (Exception ignored) {
            // Cluster not reachable; do not fail the suite.
        }
    }
}
