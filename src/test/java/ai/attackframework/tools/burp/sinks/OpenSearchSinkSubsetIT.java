package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test: create/delete/recreate subset of indices.
 */
@Tag("integration")
class OpenSearchSinkSubsetIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void create_delete_recreate_subset_settings_and_traffic() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<String> sources = List.of("settings", "traffic", "tool");

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
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception e) {
                Logger.logError("[OpenSearchSinkSubsetIT] Failed to delete index during subset test cleanup: " + r.fullName(), e);
            }
        }

        // Pass 2: re-create and verify CREATED status
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, sources);
        assertThat(second)
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));
    }
}
