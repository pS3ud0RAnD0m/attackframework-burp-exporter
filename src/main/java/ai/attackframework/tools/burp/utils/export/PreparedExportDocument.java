package ai.attackframework.tools.burp.utils.export;

import java.util.Map;

/**
 * Prepared export document shared across sinks.
 *
 * <p>Instances contain the filtered document body, the target index naming context, and the
 * stable export ID reused across OpenSearch and file sinks for the same emitted event.</p>
 *
 * @param indexName full target index name
 * @param indexKey short index key (for example {@code traffic})
 * @param exportId stable sink-shared document ID
 * @param document filtered document body with {@code document_meta.export_id} populated
 */
public record PreparedExportDocument(String indexName, String indexKey, String exportId, Map<String, Object> document) {
}
