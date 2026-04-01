package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import javax.swing.JButton;

import org.junit.jupiter.api.Test;

/**
 * Small integration check for the current ConfigPanel control surface.
 */
class ConfigPanelModelIntegrationHeadlessTest {

    @Test
    void configControl_surface_exposesImportExportAndStartButNoSave() {
        ConfigPanel panel = new ConfigPanel();

        JButton start = (JButton) findByName(panel, "control.startStop");
        assertThat(start.getText()).isIn("Start", "Stop");
        assertThat(findByText(panel, "Import Config")).isNotNull();
        assertThat(findByText(panel, "Export Config")).isNotNull();
        assertThat(findByText(panel, "Save")).isNull();
        assertThat(findByName(panel, "control.save")).isNull();
    }

    private static java.awt.Component findByName(java.awt.Container root, String name) {
        if (name.equals(root.getName())) {
            return root;
        }
        for (java.awt.Component child : root.getComponents()) {
            if (name.equals(child.getName())) {
                return child;
            }
            if (child instanceof java.awt.Container container) {
                java.awt.Component hit = findByName(container, name);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return null;
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
