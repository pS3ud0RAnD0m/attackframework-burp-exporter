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
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies sink behavior when an unknown source name is supplied.
 * Ensures no result is labeled with the unknown short name and any produced indices conform to naming rules.
 */
@Tag("integration")
class OpenSearchSinkUnsupportedSourceIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = "http://opensearch.url:9200";

    private static final Set<String> ALLOWED_SHORT_NAMES = Set.of(
            "tool", "settings", "sitemap", "findings", "traffic"
    );

    @Test
    void unknownSource_producesNoUnknownShortNames_andCleansUp() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<IndexResult> results = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("bogus"));

        // No result should carry the unknown short name.
        assertThat(results.stream().anyMatch(r -> r.shortName().equals("bogus"))).isFalse();

        // Any produced results must be from the allowed set and use correct full-name derivation.
        for (IndexResult r : results) {
            assertThat(ALLOWED_SHORT_NAMES).contains(r.shortName());
            String expectedFull = r.shortName().equals("tool")
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + r.shortName();
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Cleanup of any indices that were produced (best-effort).
        if (!results.isEmpty()) {
            OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
            for (IndexResult r : results) {
                try {
                    client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
                } catch (Exception ignored) { }
            }
        }
    }
}
