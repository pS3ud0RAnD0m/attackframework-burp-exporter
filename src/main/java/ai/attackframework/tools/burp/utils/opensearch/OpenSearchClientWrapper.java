package ai.attackframework.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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

/**
 * Wraps OpenSearch connection tests and document push operations for the exporter.
 *
 * <p>This facade coordinates OpenSearch writes with file export, retry handling, and runtime
 * authentication settings so callers can use a small API surface.</p>
 */
public class OpenSearchClientWrapper {

    /**
     * Tests OpenSearch connectivity without authentication.
     *
     * @param baseUrl OpenSearch base URL
     * @return structured connection status
     */
    public static OpenSearchStatus testConnection(String baseUrl) {
        return testConnection(baseUrl, null, null);
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Tests connectivity with optional basic auth. Performs a raw GET / so logs show the actual
     * HTTP version and status line from the wire; on 200 parses the response body for version/distribution.
     *
     * @param baseUrl OpenSearch base URL
     * @param username optional basic-auth username
     * @param password optional basic-auth password
     * @return structured connection status
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

    /**
     * Tests OpenSearch connectivity without authentication, converting runtime failures into a
     * failed status result.
     *
     * @param baseUrl OpenSearch base URL
     * @return structured connection status
     */
    public static OpenSearchStatus safeTestConnection(String baseUrl) {
        return safeTestConnection(baseUrl, null, null);
    }

    /**
     * Tests OpenSearch connectivity and converts runtime failures into a failed status result.
     *
     * @param baseUrl OpenSearch base URL
     * @param username optional basic-auth username
     * @param password optional basic-auth password
     * @return structured connection status
     */
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
    public static boolean pushDocument(String baseUrl, String indexName, String indexKey, Map<String, Object> document) {
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, document);
        FileExportService.emit(prepared);
        if (!RuntimeConfig.isOpenSearchExportEnabled() || baseUrl == null || baseUrl.isBlank()) {
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
     * Pushes documents in bulk. Delegates to the retry coordinator (retries with backoff, then
     * queue failed items).
     *
     * <p>Documents are filtered to include only fields enabled in the Fields panel before push.</p>
     *
     * <h2>Bulk-path responsibilities</h2>
     *
     * <p>The exporter deliberately uses two distinct bulk paths with different guarantees:</p>
     * <ul>
     *   <li><strong>{@code OpenSearchClientWrapper.pushBulk}</strong> (this method) is the
     *       retry-coordinated path used by one-shot <em>snapshot</em> reporters (Proxy History,
     *       Proxy WebSocket, Sitemap, Findings). It emits to every enabled file sink via
     *       {@link FileExportService#emitBatch(List)} and delegates the OpenSearch call to
     *       {@link IndexingRetryCoordinator}, which retries with backoff and queues failed items
     *       for the drain thread. Callers are expected to be small, bounded batches that can
     *       tolerate the synchronous round-trip.</li>
     *   <li><strong>{@link ChunkedBulkSender#push}</strong> is the streaming path used by the
     *       live {@code TrafficExportQueue} drain loop. It writes NDJSON directly into the POST
     *       body as the queue is drained, applies per-chunk size/byte/time caps, and tracks
     *       per-route counts via {@link ai.attackframework.tools.burp.sinks.TrafficRouteBucket}.
     *       It does <em>not</em> retry; when a bulk fails the caller is responsible for
     *       re-queuing (or dropping) items.</li>
     * </ul>
     *
     * <p>Snapshot reporters stay on {@code pushBulk} because losing retry + drain-queue fallback
     * would regress reliability for one-shot waves. Live traffic stays on
     * {@code ChunkedBulkSender} because its backpressure and streaming body are required under
     * sustained throughput. Both paths route file-sink writes through {@link FileExportService}
     * and attribute success/failure through {@link ai.attackframework.tools.burp.sinks.TrafficRouteBucket},
     * so traffic accounting is consistent regardless of which path a document takes.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param documents documents to index (each filtered by {@link ai.attackframework.tools.burp.utils.config.ExportFieldFilter})
     * @return number of documents successfully indexed
     */
    public static int pushBulk(String baseUrl, String indexName, String indexKey, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        List<PreparedExportDocument> prepared = new ArrayList<>(documents.size());
        long totalEstimatedBytes = 0;
        for (Map<String, Object> doc : documents) {
            PreparedExportDocument preparedDoc = ExportDocumentIdentity.prepare(indexName, indexKey, doc);
            prepared.add(preparedDoc);
            totalEstimatedBytes += BulkPayloadEstimator.estimateBytes(preparedDoc.document());
        }
        FileExportService.emitBatch(prepared);
        if (!RuntimeConfig.isOpenSearchExportEnabled() || baseUrl == null || baseUrl.isBlank()) {
            return RuntimeConfig.isAnyFileExportEnabled() ? prepared.size() : 0;
        }
        List<Map<String, Object>> preparedDocs = prepared.stream().map(PreparedExportDocument::document).toList();
        int successCount = IndexingRetryCoordinator.getInstance().pushBulk(baseUrl, indexName, preparedDocs, indexKey);
        if (successCount > 0 && !preparedDocs.isEmpty()) {
            long estimatedSuccessBytes = Math.round((double) totalEstimatedBytes * successCount / preparedDocs.size());
            ExportStats.recordExportedBytes(indexKey, estimatedSuccessBytes);
        }
        return successCount;
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
     * One-shot bulk with per-item failure details. Response items match request order.
     */
    static BulkResult doPushBulkWithDetails(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            // OpenSearch rejects empty bulk requests with "request body is required"; short-circuit
            // here so every reporter/bulk entry point shares the same guard as the chunked path.
            return new BulkResult(0, List.of());
        }
        try (ExportStats.BulkInFlightTicket ignored = ExportStats.openBulk()) {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl,
                    RuntimeConfig.openSearchUser(), RuntimeConfig.openSearchPassword());
            BulkRequest.Builder builder = new BulkRequest.Builder();
            for (Map<String, Object> doc : documents) {
                String exportId = ExportDocumentIdentity.exportIdOf(doc);
                builder.operations(o -> o.index(i -> i.index(indexName).id(exportId.isBlank() ? null : exportId).document(doc)));
            }
            BulkResponse response = client.bulk(builder.build());
            int successCount = 0;
            List<FailedItem> failedItems = new ArrayList<>();
            final int maxLoggedPerBulk = 3;
            int i = 0;
            int logged = 0;
            for (var item : response.items()) {
                if (item.error() == null) {
                    successCount++;
                } else {
                    var err = item.error();
                    String type = err.type() != null ? err.type() : "unknown";
                    String reason = err.reason() != null ? err.reason() : "unknown";
                    failedItems.add(new FailedItem(i, type, reason));
                    if (logged < maxLoggedPerBulk) {
                        Logger.logError(formatBulkItemFailure(indexName, i, type, reason));
                        logged++;
                    }
                }
                i++;
            }
            if (failedItems.size() > maxLoggedPerBulk) {
                Logger.logError("[OpenSearch] Bulk item failure summary: index=" + indexName
                        + " additional=" + (failedItems.size() - maxLoggedPerBulk)
                        + " totalFailed=" + failedItems.size());
            }
            return new BulkResult(successCount, failedItems);
        } catch (IOException | RuntimeException e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Logger.logDebug("doPushBulk failed for " + indexName + ": " + msg);
            if (msg.contains("request body is required")) {
                Logger.logWarnPanelOnly("[OpenSearch] Bulk request failed for "
                        + indexName + ": OpenSearch reported an empty bulk request body.");
            }
            return new BulkResult(0, List.of());
        }
    }

    /**
     * Formats one per-item bulk failure as a single structured ERROR log line.
     *
     * <p>Format is line-stable so log greps and tests can rely on it. Reason is clamped to
     * avoid a single pathological doc flooding the log panel.</p>
     */
    static String formatBulkItemFailure(String indexName, int opIndex, String type, String reason) {
        String clampedReason = reason == null ? "unknown" : reason;
        if (clampedReason.length() > 500) {
            clampedReason = clampedReason.substring(0, 497) + "...";
        }
        return "[OpenSearch] Bulk item failure: index=" + indexName
                + " op=" + opIndex
                + " type=" + (type == null || type.isBlank() ? "unknown" : type)
                + " reason=" + clampedReason;
    }

    /** Single failed bulk item: zero-based request index, OpenSearch error type, and reason. */
    record FailedItem(int index, String type, String reason) {
        FailedItem {
            type = type == null ? "unknown" : type;
            reason = reason == null ? "unknown" : reason;
        }
    }

    static final class BulkResult {
        final int successCount;
        final List<FailedItem> failedItems;

        BulkResult(int successCount, List<FailedItem> failedItems) {
            this.successCount = successCount;
            this.failedItems = failedItems != null ? List.copyOf(failedItems) : List.of();
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
