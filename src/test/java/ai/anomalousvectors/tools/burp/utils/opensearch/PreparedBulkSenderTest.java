package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

class PreparedBulkSenderTest {

    @Test
    void push_emptyDocuments_returnsZero() {
        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.push("https://opensearch.url:9200", "idx", List.of());

        assertThat(result.successCount()).isZero();
        assertThat(result.failedItems).isEmpty();
    }

    @Test
    void parseBulkResponse_delegatesToSharedParser() {
        String body = "{\"items\":[{\"index\":{\"status\":201}},{\"index\":{\"status\":201}}]}";

        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse(body, 2, "traffic-idx");

        assertThat(result.successCount()).isEqualTo(2);
        assertThat(result.failedItems).isEmpty();
    }

    @Test
    void parseBulkResponse_blankBody_countsAllAttemptedAsFailed() {
        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse("  ", 3, "traffic-idx");

        assertThat(result.successCount()).isZero();
        assertThat(result.breakdown().failed()).isEqualTo(3);
    }

    @Test
    void parseBulkResponse_malformedBody_countsAllAttemptedAsFailed() {
        OpenSearchClientWrapper.BulkResult result =
                PreparedBulkSender.parseBulkResponse("not-json", 2, "traffic-idx");

        assertThat(result.successCount()).isZero();
        assertThat(result.breakdown().failed()).isEqualTo(2);
        assertThat(result.failedItems).isEmpty();
    }

    @Test
    void preparedDocument_hasBulkBytesForFastPath() throws Exception {
        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        doc.put("meta", meta);

        PreparedExportDocument prepared = ExportDocumentIdentity.prepare("burp-exporter-test", "traffic", doc);

        assertThat(prepared.bulkNdjsonBytes()).isNotEmpty();
    }
}
