package ai.attackframework.tools.burp.sinks;

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
 * Integration test: tool-only index creation lifecycle.
 * Run via {@link OpenSearchIntegrationSuite}; tag "integration" is on the suite.
 */
class OpenSearchSinkToolOnlyIT {

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;

    @Test
    void create_delete_recreate_toolOnly_viaSink() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        List<IndexResult> first = OpenSearchReachable.createSelectedIndexes(List.of("tool"));
        assertThat(first).isNotEmpty();

        EnumSet<IndexResult.Status> allowed = EnumSet.of(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        assertThat(first).allSatisfy(r -> assertThat(allowed).contains(r.status()));

        // Validate full name
        for (IndexResult r : first) {
            assertThat(r.shortName()).isEqualTo("tool");
            assertThat(r.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX);
        }

        // Delete reported index (best-effort cleanup of dev cluster)
        OpenSearchClient client = OpenSearchReachable.getClient();
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception e) {
                Logger.logError("[OpenSearchSinkToolOnlyIT] Failed to delete index during tool-only test cleanup: " + r.fullName(), e);
            }
        }

        // Re-create and verify CREATED status
        List<IndexResult> second = OpenSearchReachable.createSelectedIndexes(List.of("tool"));
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r)
                        .extracting(IndexResult::shortName, IndexResult::fullName, IndexResult::status)
                        .containsExactly("tool", IndexNaming.INDEX_PREFIX, IndexResult.Status.CREATED));
    }
}
