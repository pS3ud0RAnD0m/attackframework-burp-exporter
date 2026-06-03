package ai.attackframework.tools.burp.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox;
import ai.attackframework.tools.burp.ui.text.ExportFieldSectionTooltips;
import ai.attackframework.tools.burp.ui.text.ExportFieldTooltips;
import ai.attackframework.tools.burp.ui.text.Tooltips;
import ai.attackframework.tools.burp.utils.config.ExportFieldCatalog;
import net.miginfocom.swing.MigLayout;

/**
 * Renders an {@link ExportFieldCatalog} tree into a hierarchical Fields sub-panel.
 */
final class ExportFieldCatalogPanel {

    /** Parent section checkbox with its toggleable descendant checkboxes. */
    static final class SectionGroup {
        final TriStateCheckBox parent;
        final List<JCheckBox> directChildren;
        final List<SectionGroup> childSections;

        SectionGroup(TriStateCheckBox parent, List<JCheckBox> directChildren, List<SectionGroup> childSections) {
            this.parent = parent;
            this.directChildren = List.copyOf(directChildren);
            this.childSections = List.copyOf(childSections);
        }

        List<SectionGroup> flattened() {
            List<SectionGroup> groups = new ArrayList<>();
            appendFlattened(groups);
            return groups;
        }

        private void appendFlattened(List<SectionGroup> groups) {
            groups.add(this);
            for (SectionGroup child : childSections) {
                child.appendFlattened(groups);
            }
        }
    }

    private static final class RenderResult {
        final List<JCheckBox> leaves;
        final SectionGroup group;

        RenderResult(List<JCheckBox> leaves, SectionGroup group) {
            this.leaves = List.copyOf(leaves);
            this.group = group;
        }
    }

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private static final int LABEL_TO_EXPANDER_GAP_PX = 4;

    private ExportFieldCatalogPanel() { }

    static List<SectionGroup> render(
            String indexName,
            JPanel target,
            ExportFieldCatalog.Node root,
            Map<String, JCheckBox> checkboxSink,
            BiConsumer<String, JLabel> requiredLabelSink,
            int checkboxTextStartInset,
            Function<String, String> requiredTooltipFor,
            int indentPx) {
        List<SectionGroup> sectionGroups = new ArrayList<>();
        int topLevelLeftGap = indentPx;
        for (ExportFieldCatalog.Node child : presentationChildren(root, "")) {
            RenderResult result = renderNode(indexName, target, child, "", topLevelLeftGap, checkboxSink,
                    requiredLabelSink, checkboxTextStartInset, requiredTooltipFor, indentPx, true);
            if (result.group != null) {
                sectionGroups.add(result.group);
            }
        }
        return sectionGroups;
    }

    static List<SectionGroup> flattenGroups(List<SectionGroup> groups) {
        List<SectionGroup> flattened = new ArrayList<>();
        if (groups == null) {
            return flattened;
        }
        for (SectionGroup group : groups) {
            flattened.addAll(group.flattened());
        }
        return flattened;
    }

    private static RenderResult renderNode(
            String indexName,
            JPanel target,
            ExportFieldCatalog.Node node,
            String parentPath,
            int leftGap,
            Map<String, JCheckBox> checkboxSink,
            BiConsumer<String, JLabel> requiredLabelSink,
            int checkboxTextStartInset,
            Function<String, String> requiredTooltipFor,
            int indentPx,
            boolean topLevel) {
        if (node.isDirectory()) {
            String sectionPath = node.path();
            boolean hasToggleableLeaves = hasToggleableDescendants(node);
            TriStateCheckBox parent = null;
            JPanel childTarget = target;
            int nestedIndent = indentPx * 2;
            int childLeftGap = leftGap + nestedIndent;
            String sectionTooltip = ExportFieldSectionTooltips.sectionTooltipFor(indexName, sectionPath);
            if (topLevel) {
                childTarget = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[grow,left]"));
                childTarget.setOpaque(false);
                childTarget.setName("fields." + indexName + ".section." + sectionPath + ".body");
                childTarget.setVisible(false);
            }
            if (hasToggleableLeaves) {
                parent = new TriStateCheckBox(node.displayTitle(), TriStateCheckBox.State.SELECTED);
                parent.setName("fields." + indexName + ".section." + sectionPath);
                Tooltips.apply(parent, sectionTooltip);
                addDirectoryHeader(indexName, target, sectionPath, parent, null, leftGap, topLevel, childTarget);
            } else {
                JLabel requiredSection = new Tooltips.HtmlLabel(node.displayTitle());
                requiredSection.setName("fields." + indexName + ".section." + sectionPath);
                requiredSection.setEnabled(false);
                Tooltips.apply(requiredSection, sectionTooltip);
                requiredLabelSink.accept(sectionPath, requiredSection);
                addDirectoryHeader(indexName, target, sectionPath, null, requiredSection, leftGap, topLevel, childTarget);
            }
            if (topLevel) {
                target.add(childTarget, "gapleft 0, growx, wrap");
            }
            List<JCheckBox> descendantCheckboxes = new ArrayList<>();
            List<JCheckBox> directCheckboxes = new ArrayList<>();
            List<SectionGroup> childGroups = new ArrayList<>();
            for (ExportFieldCatalog.Node child : presentationChildren(node, sectionPath)) {
                RenderResult result = renderNode(indexName, childTarget, child, sectionPath, childLeftGap,
                        checkboxSink, requiredLabelSink, checkboxTextStartInset, requiredTooltipFor, indentPx,
                        false);
                descendantCheckboxes.addAll(result.leaves);
                if (child.isDirectory()) {
                    if (result.group != null) {
                        childGroups.add(result.group);
                    }
                } else {
                    directCheckboxes.addAll(result.leaves);
                }
            }
            SectionGroup group = null;
            if (parent != null) {
                group = new SectionGroup(parent, directCheckboxes, childGroups);
            }
            return new RenderResult(descendantCheckboxes, group);
        }
        JCheckBox leafCheckbox = topLevel
                ? renderTopLevelLeaf(indexName, target, node, parentPath, leftGap, checkboxSink,
                        requiredLabelSink, checkboxTextStartInset, requiredTooltipFor)
                : renderLeaf(indexName, target, node, parentPath, leftGap, checkboxSink,
                        requiredLabelSink, checkboxTextStartInset, requiredTooltipFor);
        return new RenderResult(leafCheckbox == null ? List.of() : List.of(leafCheckbox), null);
    }

    private static void addDirectoryHeader(
            String indexName,
            JPanel target,
            String sectionPath,
            TriStateCheckBox selectableHeader,
            JLabel requiredHeader,
            int leftGap,
            boolean collapsible,
            java.awt.Component collapsibleBody) {
        if (!collapsible) {
            if (selectableHeader != null) {
                target.add(selectableHeader, "gapleft " + leftGap + ", gaptop 4, wrap");
            } else {
                target.add(nonSelectableDirectoryRow(requiredHeader), "gapleft " + leftGap + ", gaptop 4, wrap");
            }
            return;
        }
        String layoutColumns = selectableHeader != null
                ? "[left]" + LABEL_TO_EXPANDER_GAP_PX + "[pref!]"
                : "[pref!][left]" + LABEL_TO_EXPANDER_GAP_PX + "[pref!]";
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center", layoutColumns));
        row.setOpaque(false);
        JButton expand = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
        ConfigFieldsPanel.configureExpandButton(expand);
        expand.setName("fields." + indexName + ".section." + sectionPath + ".expand");
        Tooltips.apply(expand, Tooltips.html("Show or hide " + directoryName(selectableHeader, requiredHeader) + " fields."));
        if (selectableHeader != null) {
            row.add(selectableHeader, "aligny center");
        } else {
            row.add(invisibleCheckboxSpacer(), "aligny center");
            row.add(requiredHeader, "aligny center");
        }
        row.add(expand, "aligny center");
        target.add(row, "gapleft " + leftGap + ", gaptop 4, wrap");
        expand.addActionListener(e -> {
            if (collapsibleBody != null) {
                boolean show = !collapsibleBody.isVisible();
                collapsibleBody.setVisible(show);
                expand.setText(show ? EXPAND_EXPANDED : EXPAND_COLLAPSED);
                target.revalidate();
                target.repaint();
            }
        });
    }

    private static String directoryName(TriStateCheckBox selectableHeader, JLabel requiredHeader) {
        return selectableHeader != null ? selectableHeader.getText() : requiredHeader.getText();
    }

    private static JPanel nonSelectableDirectoryRow(JLabel requiredHeader) {
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center", "[pref!][left]"));
        row.setOpaque(false);
        row.add(invisibleCheckboxSpacer(), "aligny center");
        row.add(requiredHeader, "aligny center");
        return row;
    }

    private static java.awt.Component invisibleCheckboxSpacer() {
        JPanel spacer = new JPanel();
        spacer.setOpaque(false);
        spacer.setPreferredSize(new Tooltips.HtmlCheckBox("").getPreferredSize());
        return spacer;
    }

    private static List<ExportFieldCatalog.Node> presentationChildren(
            ExportFieldCatalog.Node node,
            String sectionPath) {
        List<ExportFieldCatalog.Node> children = new ArrayList<>(node.children());
        if (sectionPath.isEmpty()) {
            // UI-only ordering: keep mapping-derived nodes intact, but present required meta
            // fields last because Meta is the default-unselectable section in every index.
            children.sort((left, right) -> Boolean.compare(isMetaNode(left), isMetaNode(right)));
        }
        return children;
    }

    private static boolean isMetaNode(ExportFieldCatalog.Node node) {
        return "meta".equals(node.segment());
    }

    private static boolean hasToggleableDescendants(ExportFieldCatalog.Node node) {
        if (node.kind() == ExportFieldCatalog.Kind.TOGGLEABLE_LEAF) {
            return true;
        }
        for (ExportFieldCatalog.Node child : node.children()) {
            if (hasToggleableDescendants(child)) {
                return true;
            }
        }
        return false;
    }

    private static JCheckBox renderTopLevelLeaf(
            String indexName,
            JPanel target,
            ExportFieldCatalog.Node node,
            String sectionPath,
            int leftGap,
            Map<String, JCheckBox> checkboxSink,
            BiConsumer<String, JLabel> requiredLabelSink,
            int checkboxTextStartInset,
            Function<String, String> requiredTooltipFor) {
        java.awt.Component leaf = buildLeafComponent(indexName, node, sectionPath, checkboxSink,
                requiredLabelSink, checkboxTextStartInset, requiredTooltipFor);
        target.add(leaf, "gapleft " + leftGap + ", gaptop 4, wrap");
        return leaf instanceof JCheckBox checkbox ? checkbox : null;
    }

    private static JCheckBox renderLeaf(
            String indexName,
            JPanel target,
            ExportFieldCatalog.Node node,
            String sectionPath,
            int leftGap,
            Map<String, JCheckBox> checkboxSink,
            BiConsumer<String, JLabel> requiredLabelSink,
            int checkboxTextStartInset,
            Function<String, String> requiredTooltipFor) {
        java.awt.Component leaf = buildLeafComponent(indexName, node, sectionPath, checkboxSink,
                requiredLabelSink, checkboxTextStartInset, requiredTooltipFor);
        target.add(leaf, "gapleft " + leftGap + ", gaptop 0, wrap");
        return leaf instanceof JCheckBox checkbox ? checkbox : null;
    }

    private static java.awt.Component buildLeafComponent(
            String indexName,
            ExportFieldCatalog.Node node,
            String sectionPath,
            Map<String, JCheckBox> checkboxSink,
            BiConsumer<String, JLabel> requiredLabelSink,
            int checkboxTextStartInset,
            Function<String, String> requiredTooltipFor) {
        String fieldKey = node.path();
        String label = ExportFieldTooltips.checkboxLabelUnderSection(sectionPath, fieldKey);
        if (node.kind() == ExportFieldCatalog.Kind.TOGGLEABLE_LEAF) {
            JCheckBox cb = new Tooltips.HtmlCheckBox(label, true);
            cb.setName("fields." + indexName + "." + fieldKey);
            Tooltips.apply(cb, ExportFieldTooltips.tooltipFor(indexName, fieldKey));
            checkboxSink.put(fieldKey, cb);
            return cb;
        }
        if (node.kind() == ExportFieldCatalog.Kind.REQUIRED_LEAF) {
            JLabel requiredLabel = new Tooltips.HtmlLabel(label);
            requiredLabel.setName("fields." + indexName + "." + fieldKey + ".required");
            requiredLabel.setEnabled(false);
            requiredLabel.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, checkboxTextStartInset, 0, 0));
            String tooltip = requiredTooltipFor == null
                    ? ExportFieldTooltips.tooltipFor(indexName, fieldKey)
                    : requiredTooltipFor.apply(fieldKey);
            Tooltips.apply(requiredLabel, tooltip);
            requiredLabelSink.accept(fieldKey, requiredLabel);
            return requiredLabel;
        }
        return new JLabel();
    }
}
