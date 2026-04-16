package ai.attackframework.tools.burp.ui;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.ui.controller.ConfigController;

/**
 * Verifies that unselecting a Data Source greys out and disables the corresponding Fields section;
 * re-selecting re-enables it without changing checkbox selected state.
 */
class ConfigPanelFieldsSectionsEnablementHeadlessTest {

    private final ConfigPanel panel = createPanel();

    private static ConfigPanel createPanel() {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel(new ConfigController(new NoopUi()));
                if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                    p.setSize(1000, 700);
                }
                p.doLayout();
                ref.set(p);
            });
            return ref.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Failed to create ConfigPanel test fixture", e);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw new RuntimeException("Failed to create ConfigPanel test fixture", cause != null ? cause : e);
        }
    }

    @Test
    void unselecting_traffic_data_source_disables_traffic_fields_section() throws Exception {
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");
        JCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox");
        JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox");
        String[] trafficChildNames = { "trafficBurpAiCheckbox", "trafficExtensionsCheckbox", "trafficIntruderCheckbox",
                "trafficProxyCheckbox", "trafficProxyHistoryCheckbox", "trafficRepeaterCheckbox", "trafficScannerCheckbox", "trafficSequencerCheckbox" };

        // Start with at least one Traffic option selected; section should be enabled
        SwingUtilities.invokeAndWait(() -> {
            trafficProxyCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("traffic", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();

        // Deselect all Traffic options and refresh; section disabled
        SwingUtilities.invokeAndWait(() -> {
            trafficCheckbox.setSelected(false);
            for (String name : trafficChildNames) ((JCheckBox) Reflect.get(panel, name)).setSelected(false);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("traffic", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();

        // Re-select one Traffic option and refresh
        SwingUtilities.invokeAndWait(() -> {
            trafficProxyCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("traffic", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void unselecting_settings_data_source_disables_settings_fields_section() throws Exception {
        JCheckBox settingsProjectCheckbox = Reflect.get(panel, "settingsProjectCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");

        // Start with at least one Settings option selected; section should be enabled
        SwingUtilities.invokeAndWait(() -> {
            settingsProjectCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("settings", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();

        // Deselect all Settings options (parent and children) and refresh; section disabled
        JCheckBox settingsUserCheckbox = Reflect.get(panel, "settingsUserCheckbox");
        JCheckBox settingsCheckbox = Reflect.get(panel, "settingsCheckbox");
        SwingUtilities.invokeAndWait(() -> {
            settingsCheckbox.setSelected(false);
            settingsProjectCheckbox.setSelected(false);
            settingsUserCheckbox.setSelected(false);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("settings", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();

        // Re-select one Settings option and refresh
        SwingUtilities.invokeAndWait(() -> {
            settingsProjectCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("settings", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void unselecting_sitemap_data_source_disables_sitemap_fields_section() throws Exception {
        JCheckBox sitemapCheckbox = Reflect.get(panel, "sitemapCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");

        SwingUtilities.invokeAndWait(() -> {
            sitemapCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("sitemap", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();

        SwingUtilities.invokeAndWait(() -> {
            sitemapCheckbox.setSelected(false);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("sitemap", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();

        SwingUtilities.invokeAndWait(() -> {
            sitemapCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("sitemap", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void unselecting_findings_data_source_disables_findings_fields_section() throws Exception {
        JCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox");
        JCheckBox issuesCriticalCheckbox = Reflect.get(panel, "issuesCriticalCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");

        SwingUtilities.invokeAndWait(() -> {
            issuesCriticalCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("findings", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();

        JCheckBox issuesHighCheckbox = Reflect.get(panel, "issuesHighCheckbox");
        JCheckBox issuesMediumCheckbox = Reflect.get(panel, "issuesMediumCheckbox");
        JCheckBox issuesLowCheckbox = Reflect.get(panel, "issuesLowCheckbox");
        JCheckBox issuesInformationalCheckbox = Reflect.get(panel, "issuesInformationalCheckbox");
        SwingUtilities.invokeAndWait(() -> {
            issuesCheckbox.setSelected(false);
            issuesCriticalCheckbox.setSelected(false);
            issuesHighCheckbox.setSelected(false);
            issuesMediumCheckbox.setSelected(false);
            issuesLowCheckbox.setSelected(false);
            issuesInformationalCheckbox.setSelected(false);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("findings", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();

        SwingUtilities.invokeAndWait(() -> {
            issuesCriticalCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("findings", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void parent_only_selected_enables_settings_fields_section() throws Exception {
        JCheckBox settingsCheckbox = Reflect.get(panel, "settingsCheckbox");
        JCheckBox settingsProjectCheckbox = Reflect.get(panel, "settingsProjectCheckbox");
        JCheckBox settingsUserCheckbox = Reflect.get(panel, "settingsUserCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");

        SwingUtilities.invokeAndWait(() -> {
            settingsCheckbox.setSelected(true);
            settingsProjectCheckbox.setSelected(false);
            settingsUserCheckbox.setSelected(false);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("settings", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void parent_only_selected_enables_traffic_fields_section() throws Exception {
        JCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");
        String[] trafficChildNames = { "trafficBurpAiCheckbox", "trafficExtensionsCheckbox", "trafficIntruderCheckbox",
                "trafficProxyCheckbox", "trafficProxyHistoryCheckbox", "trafficRepeaterCheckbox", "trafficScannerCheckbox", "trafficSequencerCheckbox" };

        SwingUtilities.invokeAndWait(() -> {
            trafficCheckbox.setSelected(true);
            for (String name : trafficChildNames) ((JCheckBox) Reflect.get(panel, name)).setSelected(false);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("traffic", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void unselecting_exporter_source_disables_tool_fields_section() throws Exception {
        JCheckBox exporterCheckbox = Reflect.get(panel, "exporterCheckbox");
        JCheckBox exporterInfoCheckbox = Reflect.get(panel, "exporterInfoCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");
        String[] exporterChildNames = {
                "exporterTraceCheckbox", "exporterDebugCheckbox", "exporterInfoCheckbox",
                "exporterWarnCheckbox", "exporterErrorCheckbox", "exporterStatsCheckbox", "exporterConfigCheckbox"
        };

        SwingUtilities.invokeAndWait(() -> {
            exporterInfoCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("tool", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();

        SwingUtilities.invokeAndWait(() -> {
            exporterCheckbox.setSelected(false);
            for (String name : exporterChildNames) {
                ((JCheckBox) Reflect.get(panel, name)).setSelected(false);
            }
            runRefresh(panel);
        });
        assertThat(sectionEnabled("tool", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();

        SwingUtilities.invokeAndWait(() -> {
            exporterInfoCheckbox.setSelected(true);
            runRefresh(panel);
        });
        assertThat(sectionEnabled("tool", headerRows, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    private static void runRefresh(ConfigPanel panel) {
        Reflect.call(panel, "refreshFieldsSectionsEnabled");
    }

    /** Section is considered enabled if header row, sub-panel, and field checkboxes are enabled. Expand/collapse button is always left enabled. */
    private static boolean sectionEnabled(
            String indexName,
            Map<String, JPanel> headerRows,
            Map<String, JPanel> subPanels,
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex) {
        JPanel header = headerRows != null ? headerRows.get(indexName) : null;
        if (header != null && !header.isEnabled()) return false;
        JPanel sub = subPanels != null ? subPanels.get(indexName) : null;
        if (sub != null && !sub.isEnabled()) return false;
        Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex != null ? fieldCheckboxesByIndex.get(indexName) : null;
        if (checkboxes != null) {
            for (JCheckBox cb : checkboxes.values()) {
                if (!cb.isEnabled()) return false;
            }
        }
        return true;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onOpenSearchStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
