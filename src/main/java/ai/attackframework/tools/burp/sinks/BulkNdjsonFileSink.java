package ai.attackframework.tools.burp.sinks;

import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.export.ExportLineCodec;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/** Writes OpenSearch bulk-compatible NDJSON with explicit index metadata and stable IDs. */
final class BulkNdjsonFileSink extends RotatingLineFileSink {

    BulkNdjsonFileSink(Path rootDirectory, String indexName) {
        super(rootDirectory, indexName, ".ndjson");
    }

    @Override
    protected List<String> linesFor(PreparedExportDocument document) {
        try {
            return ExportLineCodec.bulkNdjsonLines(document);
        } catch (JsonProcessingException e) {
            Logger.logError("Bulk NDJSON serialize failed for " + document.indexName() + ": " + e.getMessage());
            return List.of();
        }
    }
}
