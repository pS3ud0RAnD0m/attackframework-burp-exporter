package ai.attackframework.vectors.sources.burp.sinks;

import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.vectors.sources.burp.utils.IndexNaming;
import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchConnector;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Negative-path validation: creating an index for which no mapping resource exists
 * should return FAILED and not create the index.
 */
@Tag("integration")
class OpenSearchSinkMissingMappingIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void createIndexFromResource_returnsFailed_whenMappingIsMissing() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        // Choose a short name with no corresponding mapping file.
        String shortName = "nonexistent";
        String expectedFull = IndexNaming.INDEX_PREFIX + "-" + shortName;

        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);

        // Ensure the index is absent before the test (best-effort cleanup).
        try { client.indices().delete(new DeleteIndexRequest.Builder().index(expectedFull).build()); }
        catch (Exception ignored) { }

        // Attempt creation; sink should fail due to missing resource.
        IndexResult result = OpenSearchSink.createIndexFromResource(BASE_URL, shortName);
        assertThat(result.shortName()).isEqualTo(shortName);
        assertThat(result.fullName()).isEqualTo(expectedFull);
        assertThat(result.status()).isEqualTo(IndexResult.Status.FAILED);

        // Verify the index was not created.
        boolean existsAfter = client.indices().exists(b -> b.index(expectedFull)).value();
        assertThat(existsAfter).isFalse();
    }
}
