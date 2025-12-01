package ai.attackframework.tools.burp.utils.opensearch;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.GetRequest;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.IndexResponse;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for OpenSearch connectivity, index lifecycle, and basic document operations.
 * Requires a running OpenSearch instance with security disabled at the configured URL.
 */
@Tag("integration")
class OpenSearchClientWrapperIT {

    /** Base URL for the OpenSearch development instance. */
    private static final String BASE_URL = "http://opensearch.url:9200";

    /**
     * Verifies connectivity, index creation, existence check, and cleanup.
     *
     * @throws Exception if an unexpected error occurs during the test
     */
    @Test
    void testConnection_createIndex_verify_delete() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        String indexName = "af-test-" + Instant.now().toEpochMilli();
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);

        boolean existsBefore = client.indices().exists(b -> b.index(indexName)).value();
        assertThat(existsBefore).isFalse();

        CreateIndexRequest createReq = new CreateIndexRequest.Builder()
                .index(indexName)
                .build();
        client.indices().create(createReq);

        boolean existsAfter = client.indices().exists(b -> b.index(indexName)).value();
        assertThat(existsAfter).isTrue();

        client.indices().delete(new DeleteIndexRequest.Builder().index(indexName).build());
    }

    /**
     * Verifies indexing and retrieval of a document using the official client.
     * Creates an index, indexes a document, retrieves it, validates contents, and deletes the index.
     *
     * @throws Exception if an unexpected error occurs during the test
     */
    @Test
    void indexDocument_roundTrip_thenDeleteIndex() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        String indexName = "af-doc-test-" + Instant.now().toEpochMilli();
        OpenSearchClient client = OpenSearchConnector.getClient(BASE_URL);

        client.indices().create(new CreateIndexRequest.Builder().index(indexName).build());

        Map<String, Object> doc = Map.of(
                "field", "value",
                "ts", Instant.now().toString()
        );

        IndexRequest<Map<String, Object>> indexReq = new IndexRequest.Builder<Map<String, Object>>()
                .index(indexName)
                .id("1")
                .document(doc)
                .build();

        IndexResponse indexResp = client.index(indexReq);
        String result = indexResp.result().jsonValue();
        assertThat(result.equalsIgnoreCase("created") || result.equalsIgnoreCase("updated")).isTrue();

        /*
         * Map.class is a raw type because Java does not preserve generic parameters at runtime (type erasure).
         * The OpenSearch Java client requires a Class<TDocument> for deserialization, so we cast Map.class
         * to Class<Map<String,Object>>. This cast is unchecked by the compiler because generic type
         * information is not available at runtime. The suppression is intentional and considered safe here
         * because the test controls both serialization and deserialization of the document structure.
         */
        @SuppressWarnings("unchecked")
        Class<Map<String, Object>> mapClass = (Class<Map<String, Object>>) (Class<?>) Map.class;

        GetResponse<Map<String, Object>> getResp = client.get(
                new GetRequest.Builder().index(indexName).id("1").build(),
                mapClass
        );
        assertThat(getResp.found()).isTrue();

        Map<String, Object> source = getResp.source();
        assertThat(source)
                .isNotNull()
                .containsEntry("field", "value");

        client.indices().delete(new DeleteIndexRequest.Builder().index(indexName).build());
    }
}
