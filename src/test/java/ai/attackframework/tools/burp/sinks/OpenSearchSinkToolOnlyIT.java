package ai.attackframework.tools.burp.sinks;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the minimal path: invoking the sink with an empty source list yields only the "tool" index.
 * Exercises create → delete → recreate for that single index.
 */
@Tag("integration")
class OpenSearchSinkToolOnlyIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void create_delete_recreate_toolOnly_viaSink() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        // Invoke with an empty source list; the sink derives "tool" from the naming logic.
        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of());
        assertThat(first).hasSize(1);
        IndexResult r = first.getFirst();

        // Validate short/full names and status
        assertThat(r.shortName()).isEqualTo("tool");
        assertThat(r.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX);
        assertThat(r.status()).isIn(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);

        // Delete the tool index
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
        } catch (Exception ignored) { }

        // Confirm deletion via a second call should yield CREATED
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of());
        assertThat(second).hasSize(1);
        IndexResult r2 = second.getFirst();
        assertThat(r2.shortName()).isEqualTo("tool");
        assertThat(r2.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX);
        assertThat(r2.status()).isEqualTo(IndexResult.Status.CREATED);
    }
}
