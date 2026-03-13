package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.GetMappingRequest;
import org.opensearch.client.opensearch.indices.GetMappingResponse;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchConnector;

/**
 * Validates that indices created via the sink expose a non-empty mapping on the server.
 * Run via {@link OpenSearchIntegrationSuite}; tag "integration" is on the suite.
 */
class OpenSearchSinkMappingsIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = OpenSearchReachable.BASE_URL;

    @Test
    void mappings_arePresent_andNonEmpty_onServer() throws IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        // Create standard indices via the sink (idempotent).
        List<String> sources = List.of("settings", "sitemap", "findings", "traffic");
        List<IndexResult> results = OpenSearchReachable.createSelectedIndexes(sources);
        assertThat(results).isNotEmpty();

        OpenSearchClient client = OpenSearchReachable.getClient();

        for (IndexResult r : results) {
            GetMappingResponse resp = client.indices()
                    .getMapping(new GetMappingRequest.Builder().index(r.fullName()).build());

            // Response must contain an entry for the requested index
            assertThat(resp).isNotNull();
            assertThat(resp.result()).isNotNull();
            assertThat(resp.result())
                    .as("mapping entry exists for index: " + r.fullName())
                    .containsKey(r.fullName());

            var indexMapping = resp.result().get(r.fullName());
            assertThat(indexMapping).isNotNull();
            assertThat(indexMapping.mappings()).isNotNull();
            assertThat(indexMapping.mappings().properties())
                    .as("properties present for index: " + r.fullName())
                    .isNotNull()
                    .hasSizeGreaterThan(0);
        }
    }
}
