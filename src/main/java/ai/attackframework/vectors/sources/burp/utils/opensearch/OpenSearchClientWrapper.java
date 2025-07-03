package ai.attackframework.vectors.sources.burp.utils.opensearch;

import ai.attackframework.vectors.sources.burp.utils.Logger;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.InfoResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.IndexResponse;

import java.util.Map;

public class OpenSearchClientWrapper {

    public static OpenSearchStatus testConnection(String baseUrl) {
        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            InfoResponse info = client.info();

            String version = info.version().number();
            String distribution = info.version().distribution();

            return new OpenSearchStatus(true, distribution, version, "Connection successful");

        } catch (Exception e) {
            String msg = "OpenSearch connection test failed: " + e.getMessage();
            Logger.logError(msg);
            return new OpenSearchStatus(false, "", "", msg);
        }
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl) {
        try {
            return testConnection(baseUrl);
        } catch (Exception e) {
            String msg = "OpenSearch connection test failed: " + e.getMessage();
            Logger.logError(msg);
            return new OpenSearchStatus(false, "", "", msg);
        }
    }

    public static boolean pushDocument(String baseUrl, String indexName, Map<String, Object> document) {
        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);

            IndexRequest<Map<String, Object>> request = new IndexRequest.Builder<Map<String, Object>>()
                    .index(indexName)
                    .document(document)
                    .build();

            IndexResponse response = client.index(request);
            return response.result().jsonValue().equalsIgnoreCase("created")
                    || response.result().jsonValue().equalsIgnoreCase("updated");

        } catch (Exception e) {
            Logger.logError("Failed to index document to " + indexName + ": " + e.getMessage());
            return false;
        }
    }

    public record OpenSearchStatus(boolean success, String distribution, String version, String message) {}
}
