package ai.attackframework.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ExportDocumentIdentityTest {

    @Test
    void prepare_withBlankLogicalKey_rejectsCustomPhysicalIndexName() {
        assertThatThrownBy(() -> ExportDocumentIdentity.prepare("custom-prefix-traffic", "", Map.of("message", "x")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("pass the logical index key explicitly");
    }

    @Test
    void prepare_ignoresIndexedAt_whenBuildingStableExportId() {
        Map<String, Object> firstMeta = new LinkedHashMap<>();
        firstMeta.put("schema_version", "1");
        firstMeta.put("indexed_at", "2026-01-01T00:00:00Z");
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("meta", firstMeta);
        first.put("message", "same");

        Map<String, Object> secondMeta = new LinkedHashMap<>();
        secondMeta.put("schema_version", "1");
        secondMeta.put("indexed_at", "2026-01-01T00:00:01Z");
        Map<String, Object> second = new LinkedHashMap<>();
        second.put("meta", secondMeta);
        second.put("message", "same");

        PreparedExportDocument firstPrepared = ExportDocumentIdentity.prepare("attack-traffic", "traffic", first);
        PreparedExportDocument secondPrepared = ExportDocumentIdentity.prepare("attack-traffic", "traffic", second);

        assertThat(firstPrepared.exportId()).isEqualTo(secondPrepared.exportId());
    }
}
