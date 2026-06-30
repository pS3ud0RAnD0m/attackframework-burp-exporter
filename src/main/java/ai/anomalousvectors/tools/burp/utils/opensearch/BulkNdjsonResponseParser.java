package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;

/**
 * Parses OpenSearch bulk NDJSON HTTP response bodies into success and per-item failure details.
 *
 * <p>Shared by {@link PreparedBulkSender} and {@link ChunkedBulkSender} so snapshot, live, and
 * retry paths emit identical failure logging.</p>
 */
public final class BulkNdjsonResponseParser {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_LOGGED_FAILURES = 3;

    private BulkNdjsonResponseParser() { }

    /**
     * Parsed bulk outcome with per-item failure indices aligned to the request order.
     */
    public record ParsedBulk(BulkOutcomeBreakdown breakdown, List<OpenSearchClientWrapper.FailedItem> failedItems) {

        public ParsedBulk {
            breakdown = breakdown != null ? breakdown : BulkOutcomeBreakdown.empty();
            failedItems = failedItems != null ? List.copyOf(failedItems) : List.of();
        }

        public int successCount() {
            return breakdown.successTotal();
        }
    }

    /**
     * Parses a bulk response body.
     *
     * @param responseBody raw HTTP response body
     * @param indexName index name for structured failure logs
     * @return parsed outcome; zero success when body is blank or malformed
     */
    public static ParsedBulk parse(String responseBody, String indexName) {
        if (responseBody == null || responseBody.isBlank()) {
            return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of());
        }
        try {
            JsonNode root = JSON.readTree(responseBody);
            JsonNode items = root.get("items");
            if (items == null || !items.isArray()) {
                return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of());
            }
            return parseItems((ArrayNode) items, indexName);
        } catch (IOException | RuntimeException e) {
            Logger.logDebug("[OpenSearch] BulkNdjsonResponseParser parse failed: " + e.getMessage());
            return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of());
        }
    }

    private static ParsedBulk parseItems(ArrayNode items, String indexName) {
        int created = 0;
        int updated = 0;
        int noop = 0;
        int failed = 0;
        List<OpenSearchClientWrapper.FailedItem> failedItems = new ArrayList<>();
        int logged = 0;
        String effectiveIndex = indexName == null || indexName.isBlank() ? "unknown" : indexName;

        for (int i = 0; i < items.size(); i++) {
            JsonNode item = items.get(i);
            JsonNode op = item.get("index");
            if (op == null) {
                op = item.get("create");
            }
            if (op == null) {
                op = item.get("update");
            }
            int status = (op != null && op.has("status")) ? op.get("status").asInt() : 0;
            if (status >= 200 && status < 300) {
                switch (classifyResult(op)) {
                    case "created" -> created++;
                    case "updated" -> updated++;
                    case "noop" -> noop++;
                    default -> updated++;
                }
            } else {
                failed++;
                JsonNode err = op != null ? op.get("error") : null;
                String type = err != null && err.has("type") ? err.get("type").asText() : "unknown";
                String reason = err != null && err.has("reason") ? err.get("reason").asText() : "unknown";
                failedItems.add(new OpenSearchClientWrapper.FailedItem(i, type, reason));
                if (logged < MAX_LOGGED_FAILURES) {
                    Logger.logError(OpenSearchClientWrapper.formatBulkItemFailure(effectiveIndex, i, type, reason));
                    logged++;
                }
            }
        }

        int totalFailed = failedItems.size();
        if (totalFailed > MAX_LOGGED_FAILURES) {
            Logger.logError("[OpenSearch] Bulk item failure summary: index=" + effectiveIndex
                    + " additional=" + (totalFailed - MAX_LOGGED_FAILURES)
                    + " totalFailed=" + totalFailed);
        }
        return new ParsedBulk(new BulkOutcomeBreakdown(created, updated, noop, failed), failedItems);
    }

    private static String classifyResult(JsonNode op) {
        if (op == null || !op.has("result")) {
            return "updated";
        }
        return op.get("result").asText("updated").trim().toLowerCase(Locale.ROOT);
    }
}
