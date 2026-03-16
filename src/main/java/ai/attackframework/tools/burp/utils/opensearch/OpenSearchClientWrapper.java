package ai.attackframework.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.sinks.BulkPayloadEstimator;
import ai.attackframework.tools.burp.utils.config.ExportFieldFilter;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.IndexResponse;

import ai.attackframework.tools.burp.utils.Logger;

public class OpenSearchClientWrapper {

    public static OpenSearchStatus testConnection(String baseUrl) {
        return testConnection(baseUrl, null, null);
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Tests connectivity with optional basic auth. Performs a raw GET / so logs show the actual
     * HTTP version and status line from the wire; on 200 parses the response body for version/distribution.
     */
    public static OpenSearchStatus testConnection(String baseUrl, String username, String password) {
        OpenSearchRawGet.RawGetResult result = OpenSearchRawGet.performRawGet(baseUrl, username, password);

        // Log request/response only when we actually got an HTTP response from the server.
        // For client-side failures (e.g. SSL handshake never completed), no HTTP was exchanged — do not log reconstructed request/response.
        if (result.statusCode() > 0) {
            Logger.logDebug("[OpenSearch] Request:\n" + OpenSearchLogFormat.indentRaw(result.requestForLog()));
            String responseLog = OpenSearchLogFormat.buildRawResponseWithHeaders(
                    result.body(), result.protocol(), result.statusCode(),
                    result.reasonPhrase() != null ? result.reasonPhrase() : "",
                    result.responseHeaderLines());
            Logger.logDebug("[OpenSearch] Response:\n" + OpenSearchLogFormat.indentRaw(responseLog));
        }

        if (result.statusCode() == 200) {
            String version = "";
            String distribution = "";
            if (result.body() != null && !result.body().isBlank()) {
                try {
                    JsonNode root = JSON.readTree(result.body());
                    JsonNode ver = root.path("version");
                    version = ver.path("number").asText("");
                    distribution = ver.path("distribution").asText("");
                } catch (Exception ignored) {
                    // keep empty version/distribution
                }
            }
            return new OpenSearchStatus(true, distribution, version, "Connection successful");
        }

        String msg = result.statusCode() == 0
                ? (result.reasonPhrase() != null ? result.reasonPhrase() : "Connection failed")
                : "HTTP " + result.statusCode() + (result.reasonPhrase() != null && !result.reasonPhrase().isBlank() ? " " + result.reasonPhrase() : "");
        Logger.logError("[OpenSearch] Connection failed for " + baseUrl + ": " + msg);
        return new OpenSearchStatus(false, "", "", msg);
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl) {
        return safeTestConnection(baseUrl, null, null);
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl, String username, String password) {
        try {
            return testConnection(baseUrl, username, password);
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
     * Pushes a single document. Delegates to the retry coordinator (one attempt, then queue on failure).
     *
     * <p>Documents are filtered to include only fields enabled in the Fields panel before push.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param document the document to index (filtered by {@link ai.attackframework.tools.burp.utils.config.ExportFieldFilter})
     * @return {@code true} if indexed successfully, {@code false} otherwise
     */
    public static boolean pushDocument(String baseUrl, String indexName, Map<String, Object> document) {
        String indexKey = indexKeyFromIndexName(indexName);
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, indexKey);
        boolean success = IndexingRetryCoordinator.getInstance().pushDocument(baseUrl, indexName, filtered, indexKey);
        if (success) {
            ExportStats.recordExportedBytes(indexKey, BulkPayloadEstimator.estimateBytes(filtered));
        }
        return success;
    }

    /**
     * Pushes documents in bulk. Delegates to the retry coordinator (retries with backoff, then queue failed items).
     *
     * <p>Documents are filtered to include only fields enabled in the Fields panel before push.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param documents documents to index (each filtered by {@link ai.attackframework.tools.burp.utils.config.ExportFieldFilter})
     * @return number of documents successfully indexed
     */
    public static int pushBulk(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        String indexKey = indexKeyFromIndexName(indexName);
        List<Map<String, Object>> filtered = new ArrayList<>(documents.size());
        long totalEstimatedBytes = 0;
        for (Map<String, Object> doc : documents) {
            Map<String, Object> filteredDoc = ExportFieldFilter.filterDocument(doc, indexKey);
            filtered.add(filteredDoc);
            totalEstimatedBytes += BulkPayloadEstimator.estimateBytes(filteredDoc);
        }
        int successCount = IndexingRetryCoordinator.getInstance().pushBulk(baseUrl, indexName, filtered, indexKey);
        if (successCount > 0 && !filtered.isEmpty()) {
            long estimatedSuccessBytes = Math.round((double) totalEstimatedBytes * successCount / filtered.size());
            ExportStats.recordExportedBytes(indexKey, estimatedSuccessBytes);
        }
        return successCount;
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
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl,
                    RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword());
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
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl,
                    RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword());
            BulkRequest.Builder builder = new BulkRequest.Builder();
            for (Map<String, Object> doc : documents) {
                builder.operations(o -> o.index(i -> i.index(indexName).document(doc)));
            }
            BulkResponse response = client.bulk(builder.build());
            int successCount = 0;
            List<Integer> failedIndices = new ArrayList<>();
            final int maxLoggedPerBulk = 3;
            int i = 0;
            int logged = 0;
            for (var item : response.items()) {
                if (item.error() == null) {
                    successCount++;
                } else {
                    failedIndices.add(i);
                    if (logged < maxLoggedPerBulk) {
                        var err = item.error();
                        Logger.logDebug("Bulk item error at " + i + ": " + (err != null ? err.reason() : "unknown"));
                        logged++;
                    }
                }
                i++;
            }
            if (failedIndices.size() > maxLoggedPerBulk) {
                Logger.logDebug("Bulk index " + indexName + ": " + (failedIndices.size() - maxLoggedPerBulk) + " more item errors in this batch (total failed: " + failedIndices.size() + ")");
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
