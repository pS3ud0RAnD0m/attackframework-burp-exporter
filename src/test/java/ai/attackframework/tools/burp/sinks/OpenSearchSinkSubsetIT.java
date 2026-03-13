package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Integration test: create/delete/recreate subset of indices.
 * Run via {@link OpenSearchIntegrationSuite}; tag "integration" is on the suite.
 */
class OpenSearchSinkSubsetIT {

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;
    private static final int WAIT_AFTER_DELETE_MS = 500;
    private static final int POLL_EXISTS_MAX_MS = 5_000;
    private static final int POLL_INTERVAL_MS = 100;

    @Test
    void create_delete_recreate_subset_settings_and_traffic() throws InterruptedException, IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<String> sources = List.of("settings", "traffic", "tool");

        // Pass 1: create or report existing
        List<IndexResult> first = OpenSearchReachable.createSelectedIndexes(sources);

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
        OpenSearchClient client = OpenSearchReachable.getClient();
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception e) {
                Logger.logError("[OpenSearchSinkSubsetIT] Failed to delete index during subset test cleanup: " + r.fullName(), e);
            }
        }

        // Wait for deletes to be visible before re-create
        Thread.sleep(WAIT_AFTER_DELETE_MS);
        for (IndexResult r : first) {
            long deadline = System.currentTimeMillis() + POLL_EXISTS_MAX_MS;
            while (client.indices().exists(b -> b.index(r.fullName())).value() && System.currentTimeMillis() < deadline) {
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }

        // Pass 2: re-create and verify CREATED status
        List<IndexResult> second = OpenSearchReachable.createSelectedIndexes(sources);
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));
    }
}
