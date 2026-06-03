package ai.attackframework.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ExportFieldRegistry;

class ExportFieldTooltipsTest {

    @Test
    void everyToggleableField_hasNonBlankTooltip() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            for (String field : ExportFieldRegistry.getToggleableFields(index)) {
                String tooltip = ExportFieldTooltips.tooltipFor(index, field);
                assertThat(tooltip)
                        .as(index + "." + field)
                        .isNotBlank()
                        .contains("Field:</b> " + field);
            }
        }
    }
}
