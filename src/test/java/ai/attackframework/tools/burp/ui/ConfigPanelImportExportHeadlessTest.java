package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Verifies that ConfigPanel keeps import/export affordances while removing Save.
 */
class ConfigPanelImportExportHeadlessTest {

    @Test
    void configPanel_keepsImportExportButtons_andDropsSaveButton() {
        ConfigPanel panel = new ConfigPanel();

        assertThat(findByText(panel, "Import Config")).isNotNull();
        assertThat(findByText(panel, "Export Config")).isNotNull();
        assertThat(findByText(panel, "Save")).isNull();
    }

    private static java.awt.Component findByText(java.awt.Container root, String text) {
        for (java.awt.Component child : root.getComponents()) {
            if (child instanceof javax.swing.AbstractButton button && text.equals(button.getText())) {
                return button;
            }
            if (child instanceof java.awt.Container container) {
                java.awt.Component hit = findByText(container, text);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
    }
}
