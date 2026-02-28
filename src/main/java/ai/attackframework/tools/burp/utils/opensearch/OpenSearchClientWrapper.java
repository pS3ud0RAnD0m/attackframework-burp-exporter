package ai.attackframework.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ai.attackframework.tools.burp.utils.IndexNaming;

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
            String rawRequest = OpenSearchLogFormat.buildRawRequest(baseUrl, "GET", "/", "");
            Logger.logDebug("[OpenSearch] Request:\n" + OpenSearchLogFormat.indentRaw(rawRequest));

            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            InfoResponse info = client.info();

            String version = info.version().number();
            String distribution = info.version().distribution();

            String responseBody = buildTestConnectionResponseBody(distribution, version);
            Logger.logDebug("[OpenSearch] Response:\n" + OpenSearchLogFormat.indentRaw(
                    OpenSearchLogFormat.buildRawResponse(responseBody)));

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

    /**
     * Public API: delegates to retry coordinator (one attempt + queue on failure).
     */
    public static boolean pushDocument(String baseUrl, String indexName, Map<String, Object> document) {
        String indexKey = indexKeyFromIndexName(indexName);
        return IndexingRetryCoordinator.getInstance().pushDocument(baseUrl, indexName, document, indexKey);
    }

    /**
     * Public API: delegates to retry coordinator (retries + queue failed items).
     */
    public static int pushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        String indexKey = indexKeyFromIndexName(indexName);
        return IndexingRetryCoordinator.getInstance().pushBulk(baseUrl, indexName, documents, indexKey);
    }

    static String indexKeyFromIndexName(String indexName) {
        if (indexName == null) return "tool";
        if (indexName.equals(IndexNaming.INDEX_PREFIX)) return "tool";
        if (indexName.startsWith(IndexNaming.INDEX_PREFIX + "-")) {
            return indexName.substring(IndexNaming.INDEX_PREFIX.length() + 1);
        }
        return "tool";
    }

    /**
     * One-shot index (no retry, no queue). Used by coordinator and drain thread.
     */
    static boolean doPushDocument(String baseUrl, String indexName, Map<String, Object> document) {
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
            Logger.logDebug("doPushDocument failed for " + indexName + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * One-shot bulk (no retry, no queue). Returns number of successes.
     */
    static int doPushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        BulkResult result = doPushBulkWithDetails(baseUrl, indexName, documents);
        return result.successCount;
    }

    /**
     * One-shot bulk with per-item failure details. Response items match request order.
     */
    static BulkResult doPushBulkWithDetails(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return new BulkResult(0, List.of());
        }
        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            BulkRequest.Builder builder = new BulkRequest.Builder();
            for (Map<String, Object> doc : documents) {
                builder.operations(o -> o.index(i -> i.index(indexName).document(doc)));
            }
            BulkResponse response = client.bulk(builder.build());
            int successCount = 0;
            List<Integer> failedIndices = new ArrayList<>();
            int i = 0;
            for (var item : response.items()) {
                if (item.error() == null) {
                    successCount++;
                } else {
                    failedIndices.add(i);
                    var err = item.error();
                    Logger.logDebug("Bulk item error at " + i + ": " + (err != null ? err.reason() : "unknown"));
                }
                i++;
            }
            return new BulkResult(successCount, failedIndices);
        } catch (Exception e) {
            Logger.logDebug("doPushBulk failed for " + indexName + ": " + e.getMessage());
            return new BulkResult(0, List.of());
        }
    }

    static final class BulkResult {
        final int successCount;
        final List<Integer> failedIndices;

        BulkResult(int successCount, List<Integer> failedIndices) {
            this.successCount = successCount;
            this.failedIndices = failedIndices != null ? List.copyOf(failedIndices) : List.of();
        }
    }

    public record OpenSearchStatus(boolean success, String distribution, String version, String message) {}
}
