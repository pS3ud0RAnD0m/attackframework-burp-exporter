package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.utils.ProductInfo;

class AboutPanelVersionHeadlessTest {

    private String previous;

    private void restore() {
        if (previous == null) {
            System.clearProperty("burp.exporter.version");
        } else {
            System.setProperty("burp.exporter.version", previous);
        }
    }

    @Test
    void text_includes_version_from_system_property_override() {
        try {
            previous = System.getProperty("burp.exporter.version");
            System.setProperty("burp.exporter.version", "1.2.3-test");

            AboutPanel p = new AboutPanel();
            String txt = collectVisibleText(p);
            List<JLabel> labels = findLabels(p);

            assertThat(txt)
                    .contains(ProductInfo.EXTENSION_NAME + " v1.2.3-test")
                    .contains("v1.2.3-test")
                    .contains("This Burp Suite extension continuously exports settings, sitemap, issues, and traffic into index databases")
                    .contains(ProductInfo.REPOSITORY_LABEL)
                    .contains(ProductInfo.REPOSITORY_URL)
                    .contains(ProductInfo.FRAMEWORK_OPENSEARCH_LABEL)
                    .contains(ProductInfo.FRAMEWORK_OPENSEARCH_URL);
            assertThat(txt)
                    .doesNotContain("Body export")
                    .doesNotContain("body.b64")
                    .doesNotContain("body.text")
                    .doesNotContain("gzip, x-gzip, deflate, br, zstd, compress, x-compress");
            assertThat(labels).filteredOn(label -> label.getText() != null && label.getText().startsWith("https://github.com/"))
                    .hasSize(2)
                    .allSatisfy(label -> assertThat(label.getMouseListeners()).isNotEmpty());
        } finally {
            restore();
        }
    }

    private static List<JLabel> findLabels(Container root) {
        List<JLabel> labels = new ArrayList<>();
        for (Component c : root.getComponents()) {
            if (c instanceof JLabel label) {
                labels.add(label);
            }
            if (c instanceof JScrollPane sp) {
                Component view = sp.getViewport().getView();
                if (view != null) {
                    switch (view) {
                        case Container container -> labels.addAll(findLabels(container));
                        default -> {
                        }
                    }
                }
            } else {
                if (c != null) {
                    switch (c) {
                        case Container container -> labels.addAll(findLabels(container));
                        default -> {
                        }
                    }
                }
            }
        }
        return labels;
    }

    private static String collectVisibleText(Container root) {
        StringBuilder sb = new StringBuilder();
        for (Component c : root.getComponents()) {
            if (c instanceof JLabel label) {
                sb.append(label.getText()).append('\n');
            }
            if (c instanceof JTextArea area) {
                sb.append(area.getText()).append('\n');
            }
            if (c instanceof JScrollPane sp) {
                Component view = sp.getViewport().getView();
                if (view != null) {
                    switch (view) {
                        case Container container -> sb.append(collectVisibleText(container));
                        default -> {
                        }
                    }
                }
            } else {
                if (c != null) {
                    switch (c) {
                        case Container container -> sb.append(collectVisibleText(container));
                        default -> {
                        }
                    }
                }
            }
        }
        return sb.toString();
    }
}
