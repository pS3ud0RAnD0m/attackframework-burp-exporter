package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

class ConfigPanelFieldTooltipsHeadlessTest {

    @Test
    void fieldSection_components_have_expected_tooltips() throws Exception {
        ConfigPanel panel = newPanelOnEdt();

        JLabel header = (JLabel) findLabelByText(panel, "Index Fields");
        JLabel settingsLabel = (JLabel) findLabelByTextAndTooltipPrefix(panel, "Settings", "<html><b>Settings fields</b>");
        JButton settingsExpand = findByName(panel, "fields.settings.expand", JButton.class);
        JCheckBox settingsProjectId = findByName(panel, "fields.settings.project_id", JCheckBox.class);
        JCheckBox sitemapUrl = findByName(panel, "fields.sitemap.url", JCheckBox.class);
        JCheckBox findingsSeverity = findByName(panel, "fields.findings.severity", JCheckBox.class);
        JCheckBox trafficUrl = findByName(panel, "fields.traffic.url", JCheckBox.class);
        JCheckBox trafficBurpInScope = findByName(panel, "fields.traffic.burp_in_scope", JCheckBox.class);

        runEdt(() -> {
            assertThat(header).isNotNull();
            assertThat(settingsLabel).isNotNull();
            assertThat(settingsExpand).isNotNull();
            assertThat(settingsProjectId).isNotNull();
            assertThat(sitemapUrl).isNotNull();
            assertThat(findingsSeverity).isNotNull();
            assertThat(trafficUrl).isNotNull();
            assertThat(trafficBurpInScope).isNotNull();
            assertThat(header.getToolTipText()).isEqualTo("<html>Configure which mapped fields each exported document includes.<br>These toggles affect document contents, not index creation.</html>");
            assertThat(settingsLabel.getToolTipText())
                    .isEqualTo("<html><b>Settings fields</b><br>Configure fields exported to <code>attackframework-tool-burp-settings</code>.<br>Use these toggles to trim the settings document payload.</html>");
            assertThat(settingsExpand.getToolTipText()).isEqualTo("<html>Show or hide Settings field options.</html>");
            assertThat(settingsProjectId.getText()).isEqualTo("project_id");
            assertThat(settingsProjectId.getToolTipText())
                    .isEqualTo("<html>Burp project identifier.<br><b>Source:</b> SettingsIndexReporter uses MontoyaApi.project().id().</html>");
            assertThat(sitemapUrl.getText()).isEqualTo("request.url");
            assertThat(sitemapUrl.getToolTipText())
                    .isEqualTo("<html>Full URL for the sitemap item.<br><b>Source:</b> SitemapIndexReporter.buildSitemapDoc() uses HttpRequestResponse.request().url().</html>");
            assertThat(findingsSeverity.getText()).isEqualTo("issue.severity");
            assertThat(findingsSeverity.getToolTipText())
                    .isEqualTo("<html>Issue severity.<br><b>Source:</b> FindingsIndexReporter.buildFindingDoc() uses AuditIssue.severity().</html>");
            assertThat(trafficUrl.getText()).isEqualTo("request.url");
            assertThat(trafficUrl.getToolTipText())
                    .isEqualTo("<html>Full request URL.<br><b>Source:</b> OpenSearchTrafficHandler.buildDocument() uses request.url(); ProxyHistoryIndexReporter.buildDocument() uses item.finalRequest().url(); ProxyWebSocketIndexReporter.buildDocument() uses ws.upgradeRequest().url().</html>");
            assertThat(trafficBurpInScope.getText()).isEqualTo("burp_in_scope");
            assertThat(trafficBurpInScope.getToolTipText())
                    .isEqualTo("<html>Raw Burp Suite scope flag, not the extension's export-scope decision.<br><b>Source:</b> OpenSearchTrafficHandler uses request.isInScope(); ProxyHistoryIndexReporter uses MontoyaApi.scope().isInScope(url); ProxyWebSocketIndexReporter uses MontoyaApi.scope().isInScope(url) via safeBurpInScope().</html>");
        });
    }

    @Test
    void field_checkbox_tooltip_owner_creates_html_enabled_tooltip() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JCheckBox trafficUrl = findByName(panel, "fields.traffic.url", JCheckBox.class);

        runEdt(() -> {
            assertThat(trafficUrl).isNotNull();
            JToolTip toolTip = trafficUrl.createToolTip();
            assertThat(toolTip.getComponent()).isSameAs(trafficUrl);
            assertThat(toolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel();
            panel.setSize(1000, 700);
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

    private static Component findLabelByText(Container root, String text) {
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                Component nested = findLabelByText(child, text);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static Component findLabelByTextAndTooltipPrefix(Container root, String text, String tooltipPrefix) {
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label
                    && text.equals(label.getText())
                    && label.getToolTipText() != null
                    && label.getToolTipText().startsWith(tooltipPrefix)) {
                return label;
            }
            if (component instanceof Container child) {
                Component nested = findLabelByTextAndTooltipPrefix(child, text, tooltipPrefix);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
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
}
