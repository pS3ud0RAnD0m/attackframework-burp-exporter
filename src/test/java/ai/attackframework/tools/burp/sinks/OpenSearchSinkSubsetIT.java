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
 * Verifies subset selection: requesting ["settings","traffic"] yields results for those two
 * plus "tool", and excludes other indices. Also exercises delete → recreate.
 */
@Tag("integration")
class OpenSearchSinkSubsetIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void create_delete_recreate_subset_settings_and_traffic() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        // Request a subset
        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("settings", "traffic"));
        assertThat(first).isNotEmpty();

        // Expect exactly: settings, traffic, tool (no sitemap/findings)
        Set<String> shorts = first.stream().map(IndexResult::shortName).collect(java.util.stream.Collectors.toSet());
        assertThat(shorts).containsExactlyInAnyOrder("settings", "traffic", "tool");
        assertThat(shorts).doesNotContain("sitemap", "findings");

        // Validate full names and status set
        for (IndexResult r : first) {
            String expectedFull = r.shortName().equals("tool")
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + r.shortName();
            assertThat(r.fullName()).isEqualTo(expectedFull);
            assertThat(r.status()).isIn(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        }

        // Delete reported indices
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception ignored) { }
        }

        // Recreate: all should be CREATED
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("settings", "traffic"));
        assertThat(second).hasSize(3);
        assertThat(second).allSatisfy(ir -> assertThat(ir.status()).isEqualTo(IndexResult.Status.CREATED));
    }
}
