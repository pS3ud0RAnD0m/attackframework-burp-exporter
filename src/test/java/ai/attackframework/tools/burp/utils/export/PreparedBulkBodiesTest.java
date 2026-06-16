package ai.attackframework.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class PreparedBulkBodiesTest {

    @Test
    void concatenate_joinsPreparedNdjsonBytes() throws Exception {
        Map<String, Object> firstDoc = new LinkedHashMap<>();
        firstDoc.put("message", "hello");
        firstDoc.put("meta", Map.of("schema_version", "1"));
        Map<String, Object> secondDoc = new LinkedHashMap<>();
        secondDoc.put("message", "world");
        secondDoc.put("meta", Map.of("schema_version", "1"));
        PreparedExportDocument first = ExportDocumentIdentity.prepare("attack-traffic", "traffic", firstDoc);
        PreparedExportDocument second = ExportDocumentIdentity.prepare("attack-traffic", "traffic", secondDoc);

        byte[] body = PreparedBulkBodies.concatenate(List.of(first, second));

        assertThat(body).isEqualTo(concat(first.bulkNdjsonBytes(), second.bulkNdjsonBytes()));
    }

    @Test
    void concatenate_emptyList_returnsEmptyArray() {
        assertThat(PreparedBulkBodies.concatenate(List.of())).isEmpty();
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] combined = new byte[left.length + right.length];
        System.arraycopy(left, 0, combined, 0, left.length);
        System.arraycopy(right, 0, combined, left.length, right.length);
        return combined;
    }
}
