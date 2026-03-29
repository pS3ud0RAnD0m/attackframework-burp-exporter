package ai.attackframework.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.sinks.BulkPayloadEstimator;
import ai.attackframework.tools.burp.sinks.FileExportService;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

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
        boolean credentialsProvided = username != null && !username.isBlank() && password != null && !password.isBlank();
        Logger.logDebug("[OpenSearch] Testing connection: url=" + baseUrl
                + ", tlsMode=" + OpenSearchTlsSupport.currentTlsMode()
                + ", pinnedCertificateLoaded=" + OpenSearchTlsSupport.hasPinnedCertificate()
                + ", credentialsProvided=" + credentialsProvided);
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
                } catch (IOException | RuntimeException ignored) {
                    // keep empty version/distribution
                }
            }
            OpenSearchStatus status = new OpenSearchStatus(
                    true,
                    distribution,
                    version,
                    "Connection successful",
                    "Success",
                    credentialsProvided ? "Successful" : "Not used",
                    OpenSearchTlsSupport.successTrustSummary(baseUrl)
            );
            Logger.logDebug("[OpenSearch] Connection test succeeded: auth=" + status.authenticationStatus()
                    + ", trust=" + status.trustStatus()
                    + ", version=" + status.version());
            return status;
        }

        String msg = result.statusCode() == 0
                ? (result.reasonPhrase() != null ? result.reasonPhrase() : "Connection failed")
                : "HTTP " + result.statusCode() + (result.reasonPhrase() != null && !result.reasonPhrase().isBlank() ? " " + result.reasonPhrase() : "");
        String trustStatus = OpenSearchTlsSupport.failureTrustSummary(baseUrl, msg);
        Logger.logErrorPanelOnly("[OpenSearch] Connection failed for " + baseUrl + ": " + msg
                + " | tlsMode=" + OpenSearchTlsSupport.currentTlsMode()
                + " | trust=" + trustStatus);
        String authStatus = switch (result.statusCode()) {
            case 401, 403 -> "Failed";
            case 0 -> "Not tested";
            default -> credentialsProvided ? "Attempted" : "Not used";
        };
        return new OpenSearchStatus(
                false,
                "",
                "",
                msg,
                "Failed",
                authStatus,
                trustStatus
        );
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl) {
        return safeTestConnection(baseUrl, null, null);
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl, String username, String password) {
        try {
            return testConnection(baseUrl, username, password);
        } catch (RuntimeException e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logErrorPanelOnly(sw.toString().stripTrailing());
            String trustStatus = OpenSearchTlsSupport.failureTrustSummary(baseUrl, msg);
            Logger.logErrorPanelOnly("[OpenSearch] safeTestConnection threw for " + baseUrl
                    + ": " + msg + " | tlsMode=" + OpenSearchTlsSupport.currentTlsMode()
                    + " | trust=" + trustStatus);
            return new OpenSearchStatus(
                    false,
                    "",
                    "",
                    msg,
                    "Failed",
                    "Not tested",
                    trustStatus
            );
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
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, document);
        FileExportService.emit(prepared);
        if (baseUrl == null || baseUrl.isBlank()) {
            return RuntimeConfig.isAnyFileExportEnabled();
        }
        boolean success = IndexingRetryCoordinator.getInstance().pushDocument(
                baseUrl, indexName, prepared.document(), prepared.indexKey());
        if (success) {
            ExportStats.recordExportedBytes(prepared.indexKey(), BulkPayloadEstimator.estimateBytes(prepared.document()));
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
        List<PreparedExportDocument> prepared = new ArrayList<>(documents.size());
        long totalEstimatedBytes = 0;
        for (Map<String, Object> doc : documents) {
            PreparedExportDocument preparedDoc = ExportDocumentIdentity.prepare(indexName, doc);
            prepared.add(preparedDoc);
            totalEstimatedBytes += BulkPayloadEstimator.estimateBytes(preparedDoc.document());
        }
        FileExportService.emitBatch(prepared);
        if (baseUrl == null || baseUrl.isBlank()) {
            return RuntimeConfig.isAnyFileExportEnabled() ? prepared.size() : 0;
        }
        String indexKey = indexKeyFromIndexName(indexName);
        List<Map<String, Object>> preparedDocs = prepared.stream().map(PreparedExportDocument::document).toList();
        int successCount = IndexingRetryCoordinator.getInstance().pushBulk(baseUrl, indexName, preparedDocs, indexKey);
        if (successCount > 0 && !preparedDocs.isEmpty()) {
            long estimatedSuccessBytes = Math.round((double) totalEstimatedBytes * successCount / preparedDocs.size());
            ExportStats.recordExportedBytes(indexKey, estimatedSuccessBytes);
        }
        return successCount;
    }

    static String indexKeyFromIndexName(String indexName) {
        return IndexNaming.shortNameForIndexName(indexName);
    }

    /**
     * One-shot index (no retry, no queue). Used by coordinator and drain thread.
     */
    static boolean doPushDocument(String baseUrl, String indexName, Map<String, Object> document) {
        try {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl,
                    RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword());
            String exportId = ExportDocumentIdentity.exportIdOf(document);
            IndexRequest<Map<String, Object>> request = new IndexRequest.Builder<Map<String, Object>>()
                    .index(indexName)
                    .id(exportId.isBlank() ? null : exportId)
                    .document(document)
                    .build();
            IndexResponse response = client.index(request);
            String result = response.result().jsonValue();
            return result != null && (result.equalsIgnoreCase("created") || result.equalsIgnoreCase("updated"));
        } catch (IOException | RuntimeException e) {
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
                String exportId = ExportDocumentIdentity.exportIdOf(doc);
                builder.operations(o -> o.index(i -> i.index(indexName).id(exportId.isBlank() ? null : exportId).document(doc)));
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
        } catch (IOException | RuntimeException e) {
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

    public record OpenSearchStatus(boolean success, String distribution, String version, String message,
                                   String connectionStatus, String authenticationStatus, String trustStatus) {
        /** Returns a multi-line status summary suitable for the Config destination status panel. */
        public String formattedStatus() {
            String resolvedVersion = (distribution == null || distribution.isBlank() ? "" : distribution + " ")
                    + (version == null || version.isBlank() ? "unknown" : version);
            String details = message == null || message.isBlank() ? "" : "\nDetails: " + message;
            return "Connection: " + connectionStatus
                    + "\nAuthentication: " + authenticationStatus
                    + "\nTrust: " + trustStatus
                    + "\nOpenSearch version: " + resolvedVersion.trim()
                    + details;
        }
    }
}
