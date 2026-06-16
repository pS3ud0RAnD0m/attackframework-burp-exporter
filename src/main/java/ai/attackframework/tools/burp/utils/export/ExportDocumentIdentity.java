package ai.attackframework.tools.burp.utils.export;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ExportFieldFilter;

/**
 * Filters and serializes export documents shared across sinks.
 *
 * <p>OpenSearch assigns {@code _id}; exporters do not set client-side document ids.</p>
 */
public final class ExportDocumentIdentity {

    private ExportDocumentIdentity() { }

    /** Filters and returns a sink-ready export document for the provided logical key. */
    public static PreparedExportDocument prepare(String indexName, String indexKey, Map<String, Object> document) {
        String normalizedIndexKey = indexKey == null || indexKey.isBlank()
                ? IndexNaming.requireKnownIndexKey(indexName)
                : indexKey.trim().toLowerCase(java.util.Locale.ROOT);
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, normalizedIndexKey);
        byte[] bulkNdjsonBytes;
        try {
            bulkNdjsonBytes = ExportLineCodec.bulkNdjsonBytes(filtered);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return new PreparedExportDocument(
                indexName, normalizedIndexKey, filtered, bulkNdjsonBytes.length, bulkNdjsonBytes);
    }
}
