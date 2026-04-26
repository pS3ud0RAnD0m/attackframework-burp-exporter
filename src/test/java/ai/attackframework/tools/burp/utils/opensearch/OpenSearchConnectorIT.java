package ai.attackframework.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Instant;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import ai.attackframework.tools.burp.testutils.OpenSearchReachable;
import ai.attackframework.tools.burp.testutils.OpenSearchTestConfig;

/**
 * Live-cluster integration coverage of {@link OpenSearchConnector#closeAll()}.
 *
 * <p>Complements {@link OpenSearchConnectorTest}, which exercises identity/cache contracts
 * against a never-connected dummy URL. This test verifies that a real Apache HC5 transport
 * survives a close-and-rebuild cycle: after {@code closeAll()} the next {@code getClient(...)}
 * call must yield a fresh, working client whose connection pool is not "shut down".</p>
 */
@Tag("integration")
class OpenSearchConnectorIT {

    @Test
    void closeAll_thenGetClient_rebuildsWorkingTransport() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        String indexName = "af-conn-rebuild-" + Instant.now().toEpochMilli();

        try {
            // Prime the cache with a working transport, then exercise it once so the pool is warm.
            OpenSearchClient before = OpenSearchConnector.getClient(
                    config.baseUrl(), config.username(), config.password());
            before.indices().create(new CreateIndexRequest.Builder().index(indexName).build());

            // Close everything: this is the path Stop fires asynchronously and Unload fires
            // synchronously. After this call, the cache must be empty and the next getClient(...)
            // must rebuild a new transport rather than hand out a closed one.
            OpenSearchConnector.closeAll();

            OpenSearchClient after = OpenSearchConnector.getClient(
                    config.baseUrl(), config.username(), config.password());
            assertThat(after).isNotSameAs(before);

            boolean exists = after.indices().exists(b -> b.index(indexName)).value();
            assertThat(exists).isTrue();
        } finally {
            try {
                OpenSearchClient cleanup = OpenSearchConnector.getClient(
                        config.baseUrl(), config.username(), config.password());
                cleanup.indices().delete(new DeleteIndexRequest.Builder().index(indexName).build());
            } catch (RuntimeException ignored) {
                // Best-effort cleanup for integration infrastructure.
            }
        }
    }

    @Test
    void closeAll_isIdempotent_againstLiveCluster() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        OpenSearchTestConfig config = OpenSearchTestConfig.get();

        // Prime the cache, close, close again. No call should throw, and a follow-up getClient(...)
        // must still yield a usable client. This guards the Stop-then-Unload path from regressing
        // into a NullPointerException, IllegalStateException, or "pool already shut down" surface.
        OpenSearchConnector.getClient(config.baseUrl(), config.username(), config.password());
        assertThatCode(OpenSearchConnector::closeAll).doesNotThrowAnyException();
        assertThatCode(OpenSearchConnector::closeAll).doesNotThrowAnyException();

        OpenSearchClient rebuilt = OpenSearchConnector.getClient(
                config.baseUrl(), config.username(), config.password());
        assertThat(rebuilt).isNotNull();
    }
}
