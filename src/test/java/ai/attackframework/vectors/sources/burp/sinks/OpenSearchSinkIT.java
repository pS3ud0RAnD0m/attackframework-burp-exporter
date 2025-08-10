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

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for index lifecycle using OpenSearchSink against a live test cluster.
 * Tests create, existence reporting, deletion, and re-creation of the standard indices.
 */
@Tag("integration")
class OpenSearchSinkIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = "http://opensearch.url:9200";

    /**
     * Verifies full lifecycle for the standard index set using the sink:
     * 1) Create or detect existing indices
     * 2) Delete all reported indices
     * 3) Re-create indices and verify creation status
     * 4) Validate full index naming
     */
    @Test
    void create_delete_recreate_standardIndices_viaSink() throws IOException {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<String> sources = List.of("settings", "sitemap", "findings", "traffic");

        // Pass 1: create or report existing
        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, sources);
        assertThat(first).isNotEmpty();

        EnumSet<IndexResult.Status> allowed = EnumSet.of(IndexResult.Status.CREATED, IndexResult.Status.EXISTS);
        assertThat(first).allSatisfy(r -> assertThat(allowed).contains(r.status()));

        // Validate full index naming
        for (IndexResult r : first) {
            String expectedFull = r.shortName().equals("tool")
                    ? IndexNaming.INDEX_PREFIX
                    : IndexNaming.INDEX_PREFIX + "-" + r.shortName();
            assertThat(r.fullName()).isEqualTo(expectedFull);
        }

        // Delete reported indices
        List<String> fullNames = first.stream().map(IndexResult::fullName).toList();
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (String index : fullNames) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(index).build());
            } catch (Exception ignored) { }
        }

        // Verify deletion
        for (String index : fullNames) {
            boolean exists = client.indices().exists(b -> b.index(index)).value();
            assertThat(exists).isFalse();
        }

        // Pass 2: re-create and verify CREATED status
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, sources);
        assertThat(second).isNotEmpty();
        assertThat(second).allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));

        // Short names check
        Set<String> seenShort = second.stream().map(IndexResult::shortName).collect(Collectors.toSet());
        assertThat(seenShort).contains("tool", "settings", "sitemap", "findings", "traffic");
    }

    /**
     * Verifies lifecycle for a single source ("traffic") using the sink:
     * create (or exist), delete, re-create, and full name validation.
     */
    @Test
    void create_delete_recreate_singleSource_traffic_viaSink() {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        List<IndexResult> first = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("traffic"));
        assertThat(first).isNotEmpty();

        // Validate expected short names and full names
        for (IndexResult r : first) {
            if (r.shortName().equals("tool")) {
                assertThat(r.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX);
            } else if (r.shortName().equals("traffic")) {
                assertThat(r.fullName()).isEqualTo(IndexNaming.INDEX_PREFIX + "-traffic");
            } else {
                throw new AssertionError("Unexpected short name: " + r.shortName());
            }
        }

        // Delete both indices reported
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);
        for (IndexResult r : first) {
            try {
                client.indices().delete(new DeleteIndexRequest.Builder().index(r.fullName()).build());
            } catch (Exception ignored) { }
        }

        // Re-create and verify CREATED status
        List<IndexResult> second = OpenSearchSink.createSelectedIndexes(BASE_URL, List.of("traffic"));
        assertThat(second).isNotEmpty();
        assertThat(second).allSatisfy(r -> assertThat(r.status()).isEqualTo(IndexResult.Status.CREATED));
    }
}
