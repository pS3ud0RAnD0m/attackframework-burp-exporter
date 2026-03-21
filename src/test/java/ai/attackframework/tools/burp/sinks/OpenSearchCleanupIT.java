package ai.attackframework.tools.burp.sinks;

import java.io.IOException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.utils.IndexNaming;

/**
 * Runs last in {@link OpenSearchIntegrationSuite} and deletes all test-created exporter indexes.
 *
 * <p>Cleanup is broad by design for the dedicated test OpenSearch instance: quiesce recurring
 * reporters first, then delete every {@code attackframework-*} index so no exporter state is
 * left behind after the suite.</p>
 */
public class OpenSearchCleanupIT {

    @Test
    void cleanupHelper_deletesAttackFrameworkIndexesFromDedicatedCluster() throws IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        deleteAttackFrameworkIndexesNow();

        OpenSearchReachable.createSelectedIndexes(java.util.List.of("tool", "settings", "traffic"));

        OpenSearchClient client = OpenSearchReachable.getClient();
        assertIndexExists(client, IndexNaming.INDEX_PREFIX);
        assertIndexExists(client, IndexNaming.indexNameForShortName("settings"));
        assertIndexExists(client, IndexNaming.indexNameForShortName("traffic"));

        deleteAttackFrameworkIndexesNow();

        assertIndexMissing(client, IndexNaming.INDEX_PREFIX);
        assertIndexMissing(client, IndexNaming.indexNameForShortName("settings"));
        assertIndexMissing(client, IndexNaming.indexNameForShortName("traffic"));
    }

    @AfterAll
    public static void deleteAttackFrameworkIndexesNow() {
        try {
            ExportReporterLifecycle.resetForTests();
            OpenSearchClient client = OpenSearchReachable.getClient();
            client.indices().delete(new DeleteIndexRequest.Builder()
                    .index(IndexNaming.INDEX_PREFIX + "*")
                    .allowNoIndices(true)
                    .ignoreUnavailable(true)
                    .build());
        } catch (IOException | RuntimeException ignored) {
            // Best-effort suite cleanup for the dedicated test cluster.
        }
    }

    private static void assertIndexExists(OpenSearchClient client, String indexName) throws IOException {
        boolean exists = client.indices().exists(b -> b.index(indexName)).value();
        org.assertj.core.api.Assertions.assertThat(exists).isTrue();
    }

    private static void assertIndexMissing(OpenSearchClient client, String indexName) throws IOException {
        boolean exists = client.indices().exists(b -> b.index(indexName)).value();
        org.assertj.core.api.Assertions.assertThat(exists).isFalse();
    }
}
