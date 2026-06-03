package ai.attackframework.tools.burp.ui;

import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.IntSupplier;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.attackframework.tools.burp.ui.text.ExportFieldTooltips;
import ai.attackframework.tools.burp.ui.text.Tooltips;
import ai.attackframework.tools.burp.utils.config.ExportFieldCatalog;
import ai.attackframework.tools.burp.utils.config.ExportFieldRegistry;
import net.miginfocom.swing.MigLayout;

/**
 * Builds per-index field catalogs, checkbox maps, and tri-state wiring for the Index Fields section.
 *
 * <p>Extracted from {@link ConfigPanel} so field UI assembly stays in one place alongside
 * {@link ConfigFieldsPanel} layout.</p>
 */
final class ConfigFieldsSectionBuilder {

    private ConfigFieldsSectionBuilder() { }

    /**
     * Mutable UI state produced for {@link ConfigPanel} field export wiring.
     *
     * @param fieldCheckboxesByIndex toggleable field checkboxes keyed by index then field path
     * @param requiredFieldLabelsByIndex required meta field labels per index
     * @param expandButtonsByIndex per-index expand/collapse controls
     * @param subPanelsByIndex per-index field checkbox containers
     * @param sectionHeaderRows per-index header rows for enable/disable with sources
     */
    record FieldsSectionState(
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex,
            Map<String, List<JLabel>> requiredFieldLabelsByIndex,
            Map<String, JButton> expandButtonsByIndex,
            Map<String, JPanel> subPanelsByIndex,
            Map<String, JPanel> sectionHeaderRows) {
    }

    /**
     * Builds field section UI state and wires tri-state parents to runtime config updates.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param indentPx left indent for catalog rows
     * @param checkboxTextStartInset supplier for checkbox label inset alignment
     * @param expandCollapseWiring wires each expand button to its sub-panel
     * @param runtimeConfigUpdater invoked when any field checkbox changes
     */
    static FieldsSectionState build(
            int indentPx,
            IntSupplier checkboxTextStartInset,
            BiConsumer<JButton, JPanel> expandCollapseWiring,
            ActionListener runtimeConfigUpdater) {
        Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = new LinkedHashMap<>();
        Map<String, List<JLabel>> requiredFieldLabelsByIndex = new LinkedHashMap<>();
        Map<String, JButton> expandButtonsByIndex = new LinkedHashMap<>();
        Map<String, JPanel> subPanelsByIndex = new LinkedHashMap<>();
        Map<String, JPanel> sectionHeaderRows = new LinkedHashMap<>();

        List<ExportFieldCatalogPanel.SectionGroup> fieldSectionGroups = new ArrayList<>();
        for (String indexName : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            Map<String, JCheckBox> perIndex = new LinkedHashMap<>();
            List<JLabel> requiredLabels = new ArrayList<>();
            JButton expandButton = new Tooltips.HtmlButton("+");
            expandButton.setName("fields." + indexName + ".expand");
            ConfigFieldsPanel.configureExpandButton(expandButton);
            expandButtonsByIndex.put(indexName, expandButton);

            JPanel subPanel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[grow,left]"));
            subPanel.setOpaque(false);
            ExportFieldCatalog.Node catalog = ExportFieldRegistry.getFieldCatalog(indexName);
            fieldSectionGroups.addAll(ExportFieldCatalogPanel.render(
                    indexName,
                    subPanel,
                    catalog,
                    perIndex,
                    (fieldKey, label) -> requiredLabels.add(label),
                    checkboxTextStartInset.getAsInt(),
                    fieldKey -> requiredFieldTooltip(indexName, fieldKey),
                    indentPx));

            fieldCheckboxesByIndex.put(indexName, perIndex);
            requiredFieldLabelsByIndex.put(indexName, requiredLabels);
            subPanel.setVisible(false);
            subPanelsByIndex.put(indexName, subPanel);
        }

        FieldSectionSelectionWiring.wireTriStateSectionTree(fieldSectionGroups);
        for (ExportFieldCatalogPanel.SectionGroup group : ExportFieldCatalogPanel.flattenGroups(fieldSectionGroups)) {
            group.parent.addActionListener(runtimeConfigUpdater);
        }
        for (String indexName : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            JButton expandButton = expandButtonsByIndex.get(indexName);
            JPanel subPanel = subPanelsByIndex.get(indexName);
            expandCollapseWiring.accept(expandButton, subPanel);
            for (JCheckBox checkbox : fieldCheckboxesByIndex.get(indexName).values()) {
                checkbox.addActionListener(runtimeConfigUpdater);
            }
        }

        return new FieldsSectionState(
                fieldCheckboxesByIndex,
                requiredFieldLabelsByIndex,
                expandButtonsByIndex,
                subPanelsByIndex,
                sectionHeaderRows);
    }

    private static String requiredFieldTooltip(String indexName, String fieldKey) {
        String alwaysEnabled = "<b>Note:</b> Always exported (view-only; cannot be disabled in the Fields panel)";
        String existing = ExportFieldTooltips.tooltipFor(indexName, fieldKey);
        if (existing == null || existing.equals(fieldKey) || !existing.startsWith("<html>")) {
            return "<html>" + alwaysEnabled + "</html>";
        }
        return existing.substring(0, existing.length() - "</html>".length())
                + "<br>"
                + alwaysEnabled
                + "</html>";
    }
}
