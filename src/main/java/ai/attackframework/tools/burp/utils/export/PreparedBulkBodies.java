package ai.attackframework.tools.burp.utils.export;

import java.util.List;

/**
 * Utilities for pre-serialized snapshot bulk request bodies.
 */
public final class PreparedBulkBodies {

    private PreparedBulkBodies() {}

    /**
     * Concatenates each document's pre-serialized bulk NDJSON bytes into one request body.
     *
     * @param documents prepared documents with {@link PreparedExportDocument#bulkNdjsonBytes()}
     * @return combined NDJSON body; empty when {@code documents} is empty
     */
    public static byte[] concatenate(List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return new byte[0];
        }
        int total = 0;
        for (PreparedExportDocument document : documents) {
            byte[] bytes = document.bulkNdjsonBytes();
            if (bytes != null && bytes.length > 0) {
                total += bytes.length;
            }
        }
        if (total == 0) {
            return new byte[0];
        }
        byte[] body = new byte[total];
        int offset = 0;
        for (PreparedExportDocument document : documents) {
            byte[] bytes = document.bulkNdjsonBytes();
            if (bytes == null || bytes.length == 0) {
                continue;
            }
            System.arraycopy(bytes, 0, body, offset, bytes.length);
            offset += bytes.length;
        }
        return body;
    }
}
