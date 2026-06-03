package ai.attackframework.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ExportFieldRegistry;

class ExportFieldTooltipsCoverageTest {

    private static final String GENERIC_SOURCE = "Included when this toggle is enabled in the Fields panel.";

    @Test
    void everyToggleableField_hasSpecificSource_notGenericFallback() {
        Map<String, List<String>> genericByIndex = new LinkedHashMap<>();
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            List<String> generic = new ArrayList<>();
            for (String field : ExportFieldRegistry.getToggleableFields(index)) {
                String tooltip = ExportFieldTooltips.tooltipFor(index, field);
                if (tooltip.contains(GENERIC_SOURCE)) {
                    generic.add(field);
                }
            }
            if (!generic.isEmpty()) {
                genericByIndex.put(index, generic);
            }
        }
        assertThat(genericByIndex)
                .as("toggleable fields still using genericLeafTooltip (add Description + Source in ExportFieldTooltips)")
                .isEmpty();
    }
}
