package ai.attackframework.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.InfoResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.IndexResponse;

import ai.attackframework.tools.burp.utils.Logger;

public class OpenSearchClientWrapper {

    public static OpenSearchStatus testConnection(String baseUrl) {
        try {
            Logger.logInfo("[OpenSearch] Testing connection to: " + baseUrl);

            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            InfoResponse info = client.info();

            String version = info.version().number();
            String distribution = info.version().distribution();

            Logger.logInfo("[OpenSearch] Connection successful: " + distribution + " " + version);

            return new OpenSearchStatus(true, distribution, version, "Connection successful");

        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Logger.logError("[OpenSearch] Connection failed for " + baseUrl + ": " + msg);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString().stripTrailing());
            return new OpenSearchStatus(false, "", "", msg);
        }
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl) {
        try {
            return testConnection(baseUrl);
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Logger.logError("[OpenSearch] safeTestConnection threw for " + baseUrl + ": " + msg);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString().stripTrailing());
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
