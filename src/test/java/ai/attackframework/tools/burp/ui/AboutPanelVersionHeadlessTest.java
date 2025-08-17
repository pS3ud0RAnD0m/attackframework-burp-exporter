package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Container;

import static org.assertj.core.api.Assertions.assertThat;

class AboutPanelVersionHeadlessTest {

    private String previous;

    @AfterEach
    void restore() {
        if (previous == null) {
            System.clearProperty("attackframework.version");
        } else {
            System.setProperty("attackframework.version", previous);
        }
    }

    @Test
    void text_includes_version_from_system_property_override() {
        previous = System.getProperty("attackframework.version");
        System.setProperty("attackframework.version", "1.2.3-test");

        AboutPanel p = new AboutPanel();
        JTextArea area = findTextArea(p);
        String txt = area.getText();

        // Ensure both the heading and the version marker are present.
        assertThat(txt).contains("Attack Framework: Burp Exporter");
        assertThat(txt).contains("v1.2.3-test");
    }

    private static JTextArea findTextArea(Container root) {
        for (Component c : root.getComponents()) {
            if (c instanceof JTextArea ta) return ta;
            if (c instanceof JScrollPane sp) {
                Component view = sp.getViewport().getView();
                if (view instanceof JTextArea ta) return ta;
            }
            if (c instanceof Container container) {
                JTextArea found = findTextArea(container);
                if (found != null) return found;
            }
        }
        throw new IllegalStateException("JTextArea not found");
    }
}
