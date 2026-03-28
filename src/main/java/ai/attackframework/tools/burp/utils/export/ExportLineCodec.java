package ai.attackframework.tools.burp.utils.export;

import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Serializes prepared export documents into line-oriented sink formats.
 *
 * <p>This codec centralizes the shared JSON serialization rules used by file export and the live
 * OpenSearch bulk path so NDJSON line shape, stable {@code _id} metadata, and newline handling
 * stay aligned across sinks.</p>
 */
public final class ExportLineCodec {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ExportLineCodec() { }

    /**
     * Returns one JSONL line for the provided document body.
     *
     * @param document filtered export document body
     * @return one JSON document line terminated by {@code \n}
     * @throws JsonProcessingException if serialization fails
     */
    public static String jsonDocumentLine(Map<String, Object> document) throws JsonProcessingException {
        return JSON.writeValueAsString(document) + "\n";
    }

    /**
     * Returns the two bulk NDJSON lines for the provided prepared document.
     *
     * @param document prepared export document with stable export ID
     * @return action line then document line, both terminated by {@code \n}
     * @throws JsonProcessingException if serialization fails
     */
    public static List<String> bulkNdjsonLines(PreparedExportDocument document) throws JsonProcessingException {
        return List.of(
                JSON.writeValueAsString(bulkAction(document)) + "\n",
                jsonDocumentLine(document.document())
        );
    }

    /**
     * Writes one bulk NDJSON action/document pair to the target stream.
     *
     * @param output target stream; caller retains ownership
     * @param document prepared export document with stable export ID
     * @throws IOException if serialization or writing fails
     */
    public static void writeBulkNdjson(OutputStream output, PreparedExportDocument document) throws IOException {
        JSON.writeValue(output, bulkAction(document));
        output.write('\n');
        JSON.writeValue(output, document.document());
        output.write('\n');
    }

    private static Map<String, Object> bulkAction(PreparedExportDocument document) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("_id", document.exportId());
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("index", meta);
        return action;
    }
}
