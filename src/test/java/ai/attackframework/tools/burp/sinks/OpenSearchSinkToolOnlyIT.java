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
 * Integration test: tool-only index creation lifecycle.
 */
@Tag("integration")
class OpenSearchSinkToolOnlyIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void create_delete_recreate_toolOnly_viaSink() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("tool"));
        assertThat(first).isNotEmpty();

        EnumSet<IndexResult.Status> allowed = EnumSet.of(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        assertThat(first).allSatisfy(r -> assertThat(allowed).contains(r.status()));

        // Validate full name
        for (IndexResult r : first) {
            assertThat(r.shortName()).isEqualTo("tool");
            assertThat(r.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX);
        }

        // Delete reported index (best-effort cleanup of dev cluster)
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception e) {
                Logger.logError("[OpenSearchSinkToolOnlyIT] Failed to delete index during tool-only test cleanup: " + r.fullName(), e);
            }
        }

        // Re-create and verify CREATED status
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("tool"));
        assertThat(second).isNotEmpty();
        assertThat(second).allSatisfy(r -> {
            assertThat(r.shortName()).isEqualTo("tool");
            assertThat(r.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX);
            assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED);
        });
    }
}
