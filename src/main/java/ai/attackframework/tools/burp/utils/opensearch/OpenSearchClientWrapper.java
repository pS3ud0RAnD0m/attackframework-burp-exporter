package ai.attackframework.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.InfoResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.IndexResponse;

import ai.attackframework.tools.burp.utils.Logger;

public class OpenSearchClientWrapper {

    public static OpenSearchStatus testConnection(String baseUrl) {
        try {
            // Full HTTP logging (Test connection only; not used on traffic export path).
            Logger.logDebug("[OpenSearch] --- Test connection HTTP ---");
            Logger.logDebug("[OpenSearch] Request: GET " + baseUrl + "/");
            Logger.logDebug("[OpenSearch] Request body: (none)");

            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            InfoResponse info = client.info();

            String version = info.version().number();
            String distribution = info.version().distribution();

            Logger.logDebug("[OpenSearch] Response: 200 OK");
            String responseBody = buildTestConnectionResponseBody(distribution, version);
            Logger.logDebug("[OpenSearch] Response body:\n" + responseBody);

            return new OpenSearchStatus(true, distribution, version, "Connection successful");

        } catch (Exception e) {
            Logger.logDebug("[OpenSearch] Response: (failed before or during request)");
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Logger.logError("[OpenSearch] Connection failed for " + baseUrl + ": " + msg);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logError(sw.toString().stripTrailing());
            return new OpenSearchStatus(false, "", "", msg);
        }
    }

    /** Builds a JSON-like response body for full HTTP logging (GET / cluster info). */
    private static String buildTestConnectionResponseBody(String distribution, String version) {
        return "{\"version\":{\"distribution\":\"" + escapeJson(distribution) + "\",\"number\":\"" + escapeJson(version) + "\"}}";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
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
            String result = response.result().jsonValue();
            return result != null && (result.equalsIgnoreCase("created") || result.equalsIgnoreCase("updated"));

        } catch (Exception e) {
            Logger.logError("Failed to index document to " + indexName + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Index multiple documents in one bulk request. Uses auto-generated IDs.
     *
     * @param baseUrl    OpenSearch base URL
     * @param indexName  target index
     * @param documents  documents to index (not null; empty list is a no-op)
     * @return number of documents successfully indexed, or 0 on failure or if documents is empty
     */
    public static int pushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            BulkRequest.Builder builder = new BulkRequest.Builder();
            for (Map<String, Object> doc : documents) {
                builder.operations(o -> o.index(i -> i.index(indexName).document(doc)));
            }
            BulkResponse response = client.bulk(builder.build());
            if (response.errors()) {
                int ok = 0;
                for (var item : response.items()) {
                    if (item.error() == null) {
                        ok++;
                    } else {
                        Logger.logDebug("Bulk item error: " + item.error().reason());
                    }
                }
                return ok;
            }
            return documents.size();
        } catch (Exception e) {
            Logger.logError("Bulk index failed for " + indexName + ": " + e.getMessage());
            return 0;
        }
    }

    public record OpenSearchStatus(boolean success, String distribution, String version, String message) {}
}
