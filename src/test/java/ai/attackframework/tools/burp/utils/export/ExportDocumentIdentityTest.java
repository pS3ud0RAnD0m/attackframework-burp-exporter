package ai.attackframework.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;

class ExportDocumentIdentityTest {

    @Test
    void prepare_withBlankLogicalKey_rejectsCustomPhysicalIndexName() {
        assertThatThrownBy(() -> ExportDocumentIdentity.prepare("custom-prefix-traffic", "", Map.of("message", "x")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("pass the logical index key explicitly");
    }
}
