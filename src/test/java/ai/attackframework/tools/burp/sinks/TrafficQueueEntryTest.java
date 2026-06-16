package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/** Unit tests for {@link TrafficQueueEntry}. */
class TrafficQueueEntryTest {

    @Test
    void from_preparesDocumentForTrafficIndex() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", Map.of("reporting_tool", "Repeater Tabs"));
        document.put("meta", Map.of("schema_version", "1"));

        TrafficQueueEntry entry = TrafficQueueEntry.from(document);

        assertThat(entry).isNotNull();
        PreparedExportDocument prepared = entry.prepared();
        assertThat(prepared.document()).containsEntry("burp", document.get("burp"));
        assertThat(prepared.estimatedBulkBytes()).isPositive();
        assertThat(prepared.bulkNdjsonBytes()).isNotNull();
        assertThat(prepared.bulkNdjsonBytes().length).isPositive();
    }
}
