package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox;

class ConfigPanelFieldCatalogLayoutHeadlessTest {

    @Test
    void traffic_fields_use_nested_headers_with_current_level_labels() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton trafficExpand = findByName(panel, "fields.traffic.expand", JButton.class);
        JButton burpExpand = findByName(panel, "fields.traffic.section.burp.expand", JButton.class);
        JPanel burpBody = findByName(panel, "fields.traffic.section.burp.body", JPanel.class);
        TriStateCheckBox burpSection = findByName(panel, "fields.traffic.section.burp", TriStateCheckBox.class);
        TriStateCheckBox proxySection = findByName(panel, "fields.traffic.section.burp.proxy", TriStateCheckBox.class);
        JButton requestExpand = findByName(panel, "fields.traffic.section.request.expand", JButton.class);
        JPanel requestBody = findByName(panel, "fields.traffic.section.request.body", JPanel.class);
        TriStateCheckBox requestBodySection = findByName(panel, "fields.traffic.section.request.body", TriStateCheckBox.class);
        TriStateCheckBox requestProtocolSection = findByName(panel, "fields.traffic.section.request.protocol", TriStateCheckBox.class);
        JCheckBox reporter = findByName(panel, "fields.traffic.burp.reporting_tool", JCheckBox.class);
        JCheckBox proxyHistoryId = findByName(panel, "fields.traffic.burp.proxy.history_id", JCheckBox.class);
        JCheckBox requestBodyB64 = findByName(panel, "fields.traffic.request.body.b64", JCheckBox.class);
        JCheckBox scheme = findByName(panel, "fields.traffic.request.protocol.scheme", JCheckBox.class);

        runEdt(() -> {
            trafficExpand.doClick();
            assertThat(burpExpand).isNotNull();
            assertThat(burpExpand.getText()).isEqualTo("+");
            JToolTip burpExpandTooltip = burpExpand.createToolTip();
            assertThat(burpExpandTooltip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            assertThat(burpExpand.getToolTipText()).isEqualTo("<html>Show or hide Burp fields.</html>");
            assertThat(burpBody).isNotNull();
            assertThat(burpBody.isVisible()).isFalse();
            assertThat(burpSection).isNotNull();
            assertThat(burpSection.getText()).isEqualTo("Burp");
            assertThat(scheme).isNotNull();
            assertThat(scheme.getText()).isEqualTo("Scheme");
            assertThat(findByName(panel, "fields.traffic.scheme", JCheckBox.class)).isNull();
            burpExpand.doClick();
            assertThat(burpExpand.getText()).isEqualTo("−");
            assertThat(burpBody.isVisible()).isTrue();
            assertThat(proxySection).isNotNull();
            assertThat(proxySection.getText()).isEqualTo("Proxy");
            assertThat(requestExpand).isNotNull();
            assertThat(requestExpand.getText()).isEqualTo("+");
            assertThat(requestBody).isNotNull();
            assertThat(requestBody.isVisible()).isFalse();
            requestExpand.doClick();
            assertThat(requestExpand.getText()).isEqualTo("−");
            assertThat(requestBody.isVisible()).isTrue();
            assertThat(requestBodySection).isNotNull();
            assertThat(requestBodySection.getText()).isEqualTo("Body");
            assertThat(requestProtocolSection).isNotNull();
            assertThat(requestProtocolSection.getText()).isEqualTo("Protocol");
            assertThat(findByName(panel, "fields.traffic.section.proxy", TriStateCheckBox.class)).isNull();
            assertThat(findByName(panel, "fields.traffic.burp", JCheckBox.class)).isNull();
            assertThat(reporter).isNotNull();
            assertThat(reporter.getText()).isEqualTo("Reporting tool");
            assertThat(proxyHistoryId).isNotNull();
            assertThat(proxyHistoryId.getText()).isEqualTo("History id");
            assertThat(requestBodyB64).isNotNull();
            assertThat(requestBodyB64.getText()).isEqualTo("B64");
            assertThat(componentOrder(
                    findByName(panel, "fields.traffic.section.websocket", TriStateCheckBox.class),
                    findByName(panel, "fields.traffic.section.meta", JLabel.class),
                    panel))
                    .isLessThan(0);
        });
    }

    @Test
    void meta_sections_renderLastBecauseTheyAreDefaultUnselectable() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton settingsExpand = findByName(panel, "fields.settings.expand", JButton.class);
        JButton trafficExpand = findByName(panel, "fields.traffic.expand", JButton.class);

        runEdt(() -> {
            settingsExpand.doClick();
            trafficExpand.doClick();

            assertThat(componentOrder(
                    findByName(panel, "fields.settings.user", JCheckBox.class),
                    findByName(panel, "fields.settings.section.meta", JLabel.class),
                    panel))
                    .isLessThan(0);
            assertThat(componentOrder(
                    findByName(panel, "fields.traffic.section.websocket", TriStateCheckBox.class),
                    findByName(panel, "fields.traffic.section.meta", JLabel.class),
                    panel))
                    .isLessThan(0);
        });
    }

    @Test
    void traffic_websocketSection_exposesNestedPayloadAndDiscriminatorFields() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton trafficExpand = findByName(panel, "fields.traffic.expand", JButton.class);
        TriStateCheckBox websocketSection = findByName(panel, "fields.traffic.section.websocket", TriStateCheckBox.class);
        JButton websocketExpand = findByName(panel, "fields.traffic.section.websocket.expand", JButton.class);
        JPanel websocketBody = findByName(panel, "fields.traffic.section.websocket.body", JPanel.class);
        TriStateCheckBox payloadSection = findByName(panel, "fields.traffic.section.websocket.payload", TriStateCheckBox.class);
        JCheckBox isWebSocket = findByName(panel, "fields.traffic.websocket.is_websocket", JCheckBox.class);
        JCheckBox direction = findByName(panel, "fields.traffic.websocket.direction", JCheckBox.class);
        JCheckBox payloadText = findByName(panel, "fields.traffic.websocket.payload.text", JCheckBox.class);
        JCheckBox payloadB64 = findByName(panel, "fields.traffic.websocket.payload.b64", JCheckBox.class);

        runEdt(() -> {
            trafficExpand.doClick();
            assertThat(websocketSection).isNotNull();
            assertThat(websocketSection.getText()).isEqualTo("WebSocket");
            assertThat(websocketExpand).isNotNull();
            assertThat(websocketBody).isNotNull();
            assertThat(websocketBody.isVisible()).isFalse();
            websocketExpand.doClick();
            assertThat(websocketBody.isVisible()).isTrue();
            assertThat(payloadSection).isNotNull();
            assertThat(payloadSection.getText()).isEqualTo("Payload");
            assertThat(isWebSocket).isNotNull();
            assertThat(isWebSocket.getText()).isEqualTo("Is websocket");
            assertThat(direction).isNotNull();
            assertThat(direction.getText()).isEqualTo("Direction");
            assertThat(payloadText).isNotNull();
            assertThat(payloadText.getText()).isEqualTo("Text");
            assertThat(payloadB64).isNotNull();
            assertThat(payloadB64.getText()).isEqualTo("B64");
        });
    }

    @Test
    void collaboratorFields_areFindingsOnlyAndNotTraffic() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        assertThat(findByName(panel, "fields.traffic.section.collaborator", TriStateCheckBox.class)).isNull();
        assertThat(findByName(panel, "fields.traffic.collaborator.type", JCheckBox.class)).isNull();
        assertThat(findByName(panel, "fields.findings.section.collaborator", TriStateCheckBox.class)).isNotNull();
        assertThat(findByName(panel, "fields.findings.collaborator.id", JCheckBox.class)).isNotNull();
    }

    @Test
    void childSectionExpanders_renderToTheRightOfSectionLabels() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JButton findingsExpand = findByName(panel, "fields.findings.expand", JButton.class);
        JButton findingsBurpExpand = findByName(panel, "fields.findings.section.burp.expand", JButton.class);
        TriStateCheckBox findingsBurpSection = findByName(panel, "fields.findings.section.burp", TriStateCheckBox.class);

        runEdt(() -> {
            findingsExpand.doClick();
            layoutTree(panel);

            assertThat(xInRoot(findingsBurpExpand, panel))
                    .as("child section expander should render after the sub-field label")
                    .isGreaterThan(xInRoot(findingsBurpSection, panel));
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel();
            panel.setSize(1000, 900);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static <T extends java.awt.Component> T findByName(Container root, String name, Class<T> type) {
        for (java.awt.Component component : root.getComponents()) {
            String componentName = component.getName();
            if (type.isInstance(component) && componentName != null && name.equals(componentName)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static int componentOrder(Component first, Component second, Container root) {
        int firstIndex = componentIndex(first, root, new int[] {0});
        int secondIndex = componentIndex(second, root, new int[] {0});
        assertThat(firstIndex).isGreaterThanOrEqualTo(0);
        assertThat(secondIndex).isGreaterThanOrEqualTo(0);
        return Integer.compare(firstIndex, secondIndex);
    }

    private static int xInRoot(Component component, Container root) {
        return SwingUtilities.convertPoint(component.getParent(), component.getLocation(), root).x;
    }

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component component : container.getComponents()) {
            if (component instanceof Container child) {
                layoutTree(child);
            }
        }
    }

    private static int componentIndex(Component target, Container root, int[] index) {
        for (Component component : root.getComponents()) {
            if (component == target) {
                return index[0];
            }
            index[0]++;
            if (component instanceof Container child) {
                int nested = componentIndex(target, child, index);
                if (nested >= 0) {
                    return nested;
                }
            }
        }
        return -1;
    }

}
