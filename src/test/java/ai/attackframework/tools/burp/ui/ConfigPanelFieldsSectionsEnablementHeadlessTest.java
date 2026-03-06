package ai.attackframework.tools.burp.ui;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.ui.controller.ConfigController;

/**
 * Verifies that unselecting a Data Source greys out and disables the corresponding Fields section;
 * re-selecting re-enables it without changing checkbox selected state.
 */
class ConfigPanelFieldsSectionsEnablementHeadlessTest {

    private ConfigPanel panel;

    @BeforeEach
    void setup() throws Exception {
        var ref = new java.util.concurrent.atomic.AtomicReference<ConfigPanel>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new NoopUi()));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();
            ref.set(p);
        });
        panel = ref.get();
    }

    @Test
    void unselecting_traffic_data_source_disables_traffic_fields_section() throws Exception {
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JButton> expandButtons = Reflect.get(panel, "fieldsExpandButtons");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");
        JCheckBox trafficCheckbox = getTrafficCheckbox();
        var refreshMethod = ConfigPanel.class.getDeclaredMethod("refreshFieldsSectionsEnabled");
        refreshMethod.setAccessible(true);

        // Start with Traffic selected and refresh; section should be enabled
        SwingUtilities.invokeAndWait(() -> {
            trafficCheckbox.setSelected(true);
            runRefresh(panel, refreshMethod);
        });
        assertThat(sectionEnabled("traffic", headerRows, expandButtons, subPanels, fieldCheckboxesByIndex)).isTrue();

        // Unselect Traffic and refresh
        SwingUtilities.invokeAndWait(() -> {
            trafficCheckbox.setSelected(false);
            runRefresh(panel, refreshMethod);
        });
        assertThat(sectionEnabled("traffic", headerRows, expandButtons, subPanels, fieldCheckboxesByIndex)).isFalse();

        // Re-select and refresh
        SwingUtilities.invokeAndWait(() -> {
            trafficCheckbox.setSelected(true);
            runRefresh(panel, refreshMethod);
        });
        assertThat(sectionEnabled("traffic", headerRows, expandButtons, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @Test
    void unselecting_settings_data_source_disables_settings_fields_section() throws Exception {
        JCheckBox settingsCheckbox = Reflect.get(panel, "settingsCheckbox");
        Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
        Map<String, JButton> expandButtons = Reflect.get(panel, "fieldsExpandButtons");
        Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");
        var refreshMethod = ConfigPanel.class.getDeclaredMethod("refreshFieldsSectionsEnabled");
        refreshMethod.setAccessible(true);

        // Start with Settings selected; section should be enabled
        SwingUtilities.invokeAndWait(() -> {
            settingsCheckbox.setSelected(true);
            runRefresh(panel, refreshMethod);
        });
        assertThat(sectionEnabled("settings", headerRows, expandButtons, subPanels, fieldCheckboxesByIndex)).isTrue();

        // Unselect Settings and refresh
        SwingUtilities.invokeAndWait(() -> {
            settingsCheckbox.setSelected(false);
            runRefresh(panel, refreshMethod);
        });
        assertThat(sectionEnabled("settings", headerRows, expandButtons, subPanels, fieldCheckboxesByIndex)).isFalse();

        // Re-select and refresh
        SwingUtilities.invokeAndWait(() -> {
            settingsCheckbox.setSelected(true);
            runRefresh(panel, refreshMethod);
        });
        assertThat(sectionEnabled("settings", headerRows, expandButtons, subPanels, fieldCheckboxesByIndex)).isTrue();
    }

    @SuppressWarnings("unchecked")
    private JCheckBox getTrafficCheckbox() throws Exception {
        return Reflect.get(panel, "trafficCheckbox");
    }

    private static void runRefresh(ConfigPanel panel, Method refreshMethod) {
        try {
            refreshMethod.invoke(panel);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    /** Section is considered enabled if header row, sub-panel, and field checkboxes are enabled. Expand/collapse button is always left enabled. */
    private static boolean sectionEnabled(
            String indexName,
            Map<String, JPanel> headerRows,
            Map<String, JButton> expandButtons,
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
