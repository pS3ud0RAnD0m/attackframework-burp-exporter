package ai.anomalousvectors.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ExportFieldTooltipsLabelTest {

    @Test
    void checkboxLabelUnderSection_stripsSectionPrefix() {
        assertThat(ExportFieldTooltips.checkboxLabelUnderSection("burp", "burp.is_in_scope"))
                .isEqualTo("Is in scope");
        assertThat(ExportFieldTooltips.checkboxLabelUnderSection("request", "request.url"))
                .isEqualTo("Url");
    }

    @Test
    void checkboxLabelUnderSection_withoutSection_keepsFullPath() {
        assertThat(ExportFieldTooltips.checkboxLabelUnderSection("burp", "burp.repeater.tab_group"))
                .isEqualTo("Repeater.tab group");
        assertThat(ExportFieldTooltips.checkboxLabelUnderSection("burp", "burp.repeater.tab_name"))
                .isEqualTo("Repeater.tab name");
    }
}
