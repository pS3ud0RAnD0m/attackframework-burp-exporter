package ai.attackframework.tools.burp.sinks;

import java.util.List;

import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/**
 * Contract for file-based export sinks.
 *
 * <p>Implementations append prepared exporter documents to disk in a sink-specific format such as
 * JSONL or bulk-compatible NDJSON.</p>
 */
public interface FileSink {

    /** Estimates the number of bytes that would be appended for one prepared document. */
    long estimateBytes(PreparedExportDocument document);

    /** Appends one prepared document to disk. */
    long appendDocument(PreparedExportDocument document);

    /** Appends a batch of prepared documents to disk. */
    default long appendBatch(List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0L;
        }
        long written = 0L;
        for (PreparedExportDocument document : documents) {
            written += appendDocument(document);
        }
        return written;
    }
}
