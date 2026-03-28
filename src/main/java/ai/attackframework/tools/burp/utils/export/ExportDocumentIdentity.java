package ai.attackframework.tools.burp.utils.export;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ExportFieldFilter;

/**
 * Builds stable exporter IDs shared across sinks.
 *
 * <p>The ID is derived from the filtered document content plus the target index name. This makes
 * the same emitted event reuse one ID across OpenSearch, bulk NDJSON, and JSONL while still
 * allowing later events to produce distinct IDs when their document content differs.</p>
 */
public final class ExportDocumentIdentity {

    private static final String DOCUMENT_META = "document_meta";
    private static final String EXPORT_ID = "export_id";
    private static final ObjectMapper CANONICAL_JSON = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private ExportDocumentIdentity() { }

    /** Filters, stamps, and returns a sink-ready export document. */
    public static PreparedExportDocument prepare(String indexName, Map<String, Object> document) {
        String indexKey = IndexNaming.shortNameForIndexName(indexName);
        Map<String, Object> filtered = ExportFieldFilter.filterDocument(document, indexKey);
        String exportId = buildStableId(indexName, filtered);
        Map<String, Object> withId = withExportId(filtered, exportId);
        return new PreparedExportDocument(indexName, indexKey, exportId, withId);
    }

    /** Returns the export ID stored in {@code document_meta.export_id}, or blank when absent. */
    @SuppressWarnings("unchecked")
    public static String exportIdOf(Map<String, Object> document) {
        if (document == null) {
            return "";
        }
        Object metaObj = document.get(DOCUMENT_META);
        if (metaObj instanceof Map<?, ?> metaMap) {
            Object idObj = ((Map<String, Object>) metaMap).get(EXPORT_ID);
            return idObj == null ? "" : String.valueOf(idObj);
        }
        return "";
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> withExportId(Map<String, Object> filtered, String exportId) {
        Map<String, Object> copy = new LinkedHashMap<>(filtered);
        Object metaObj = copy.get(DOCUMENT_META);
        Map<String, Object> meta = metaObj instanceof Map<?, ?> existing
                ? new LinkedHashMap<>((Map<String, Object>) existing)
                : new LinkedHashMap<>();
        meta.put(EXPORT_ID, exportId);
        copy.put(DOCUMENT_META, meta);
        return copy;
    }

    @SuppressWarnings("unchecked")
    private static String buildStableId(String indexName, Map<String, Object> filtered) {
        Map<String, Object> canonicalDoc = new LinkedHashMap<>(filtered);
        Object metaObj = canonicalDoc.get(DOCUMENT_META);
        if (metaObj instanceof Map<?, ?> existing) {
            Map<String, Object> meta = new LinkedHashMap<>((Map<String, Object>) existing);
            meta.remove(EXPORT_ID);
            canonicalDoc.put(DOCUMENT_META, meta);
        }
        byte[] payload;
        try {
            payload = CANONICAL_JSON.writeValueAsBytes(canonicalDoc);
        } catch (JsonProcessingException e) {
            payload = String.valueOf(canonicalDoc).getBytes(StandardCharsets.UTF_8);
        }
        MessageDigest digest = sha256();
        digest.update(indexName.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
        digest.update(payload);
        return toHex(digest.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
