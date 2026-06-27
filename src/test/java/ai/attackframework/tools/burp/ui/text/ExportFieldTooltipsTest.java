package ai.attackframework.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

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

    @Test
    void tooltips_doNotDescribeRemovedDynamicHeaderFields() {
        for (String index : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            for (String field : ExportFieldRegistry.getToggleableFields(index)) {
                assertNoRemovedDynamicHeaderCopy(index + "." + field, ExportFieldTooltips.tooltipFor(index, field));
            }
        }
        for (String field : List.of(
                "requests_responses.request.header",
                "requests_responses.response.header",
                "collaborator.http.request.header",
                "collaborator.http.response.header")) {
            String tooltip = ExportFieldTooltipsFindings.findingsTooltip(field);
            assertNoRemovedDynamicHeaderCopy("findings." + field, tooltip);
            assertThat(tooltip).as(field).contains("ordered rows");
        }
    }

    private static void assertNoRemovedDynamicHeaderCopy(String field, String tooltip) {
        assertThat(tooltip)
                .as(field)
                .doesNotContain("lower-case dynamic")
                .doesNotContain("request.header.<")
                .doesNotContain("response.header.<")
                .doesNotContain("content-type_inferred");
    }
}
