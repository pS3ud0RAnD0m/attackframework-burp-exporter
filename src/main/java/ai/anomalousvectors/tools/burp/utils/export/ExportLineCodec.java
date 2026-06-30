package ai.anomalousvectors.tools.burp.utils.export;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Serializes prepared export documents into line-oriented sink formats.
 */
public final class ExportLineCodec {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ExportLineCodec() { }

    /**
     * Returns one JSONL line for the provided document body.
     */
    public static String jsonDocumentLine(Map<String, Object> document) throws JsonProcessingException {
        return JSON.writeValueAsString(document) + "\n";
    }

    /**
     * Returns the two bulk NDJSON lines for the provided prepared document.
     */
    public static List<String> bulkNdjsonLines(PreparedExportDocument document) throws JsonProcessingException {
        return List.of(
                JSON.writeValueAsString(bulkIndexAction()) + "\n",
                jsonDocumentLine(document.document())
        );
    }

    /**
     * Writes one bulk NDJSON action/document pair to the target stream.
     */
    public static void writeBulkNdjson(OutputStream output, PreparedExportDocument document) throws IOException {
        JSON.writeValue(output, bulkIndexAction());
        output.write('\n');
        JSON.writeValue(output, document.document());
        output.write('\n');
    }

    /** Returns the bulk NDJSON action/document pair bytes for one document body. */
    public static byte[] bulkNdjsonBytes(Map<String, Object> document) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        JSON.writeValue(output, bulkIndexAction());
        output.write('\n');
        JSON.writeValue(output, document);
        output.write('\n');
        return output.toByteArray();
    }

    private static Map<String, Object> bulkIndexAction() {
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("index", Map.of());
        return action;
    }
}
