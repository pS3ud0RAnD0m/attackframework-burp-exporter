package ai.anomalousvectors.tools.burp.utils.export;

import java.util.Map;

/**
 * Prepared export document shared across sinks.
 *
 * @param indexName full target index name
 * @param indexKey short index key (for example {@code traffic})
 * @param document filtered document body
 * @param estimatedBulkBytes approximate serialized bulk payload size in bytes for chunk sizing
 * @param bulkNdjsonBytes pre-serialized bulk action+document NDJSON pair for OpenSearch flush
 */
public record PreparedExportDocument(
        String indexName,
        String indexKey,
        Map<String, Object> document,
        long estimatedBulkBytes,
        byte[] bulkNdjsonBytes) {
}
