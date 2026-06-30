package ai.anomalousvectors.tools.burp.ui;

import java.awt.event.ItemEvent;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JCheckBox;

import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;

/**
 * Tri-state parent checkbox wiring for hierarchical field/source selection UIs.
 *
 * <p>All {@code wire*} methods register Swing listeners; callers must invoke them on the EDT.</p>
 */
final class FieldSectionSelectionWiring {

    private FieldSectionSelectionWiring() { }

    /**
     * Wires tri-state section parents to descendant leaf checkboxes across {@code rootGroups}.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param rootGroups catalog section roots built by {@link ExportFieldCatalogPanel}
     */
    static void wireTriStateSectionTree(List<ExportFieldCatalogPanel.SectionGroup> rootGroups) {
        List<ExportFieldCatalogPanel.SectionGroup> safeRootGroups = rootGroups == null ? List.of() : rootGroups;
        AtomicBoolean syncing = new AtomicBoolean(false);
        Runnable refreshAll = () -> {
            for (ExportFieldCatalogPanel.SectionGroup group : safeRootGroups) {
                refreshGroupState(group);
            }
        };

        for (ExportFieldCatalogPanel.SectionGroup group : safeRootGroups) {
            wireGroup(group, safeRootGroups, syncing, refreshAll);
        }

        syncing.set(true);
        try {
            refreshAll.run();
        } finally {
            syncing.set(false);
        }
    }

    /**
     * Wires one tri-state parent to its direct leaf checkboxes.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param parent section tri-state checkbox
     * @param children toggleable leaf checkboxes under the section
     */
    static void wireTriStateParentChild(TriStateCheckBox parent, List<JCheckBox> children) {
        List<JCheckBox> safeChildren = children == null ? List.of() : children;
        AtomicBoolean syncing = new AtomicBoolean(false);
        int[] selectedCount = new int[1];
        int[] enabledCount = new int[1];

        Runnable refreshCounts = () -> {
            int selected = 0;
            int enabledChildren = 0;
            for (JCheckBox c : safeChildren) {
                if (!c.isEnabled()) {
                    continue;
                }
                enabledChildren++;
                if (c.isSelected()) {
                    selected++;
                }
            }
            selectedCount[0] = selected;
            enabledCount[0] = enabledChildren;
        };

        Runnable syncParentFromCounts = () -> {
            if (safeChildren.isEmpty()) {
                return;
            }
            int selected = selectedCount[0];
            int enabledChildren = enabledCount[0];
            if (enabledChildren == 0 || selected == 0) {
                parent.setState(TriStateCheckBox.State.DESELECTED);
            } else if (selected == enabledChildren) {
                parent.setState(TriStateCheckBox.State.SELECTED);
            } else {
                parent.setState(TriStateCheckBox.State.INDETERMINATE);
            }
        };

        for (JCheckBox child : safeChildren) {
            child.addItemListener(e -> {
                if (syncing.get()) {
                    return;
                }
                syncing.set(true);
                try {
                    if (child.isEnabled()) {
                        selectedCount[0] += e.getStateChange() == ItemEvent.SELECTED ? 1 : -1;
                    } else {
                        refreshCounts.run();
                    }
                    syncParentFromCounts.run();
                } finally {
                    syncing.set(false);
                }
            });
            child.addPropertyChangeListener("enabled", e -> {
                if (syncing.get()) {
                    return;
                }
                syncing.set(true);
                try {
                    refreshCounts.run();
                    syncParentFromCounts.run();
                } finally {
                    syncing.set(false);
                }
            });
        }

        parent.addActionListener(e -> {
            if (syncing.get()) {
                return;
            }
            syncing.set(true);
            try {
                boolean selectAll = parent.getState() != TriStateCheckBox.State.DESELECTED;
                for (JCheckBox child : safeChildren) {
                    if (!child.isEnabled()) {
                        continue;
                    }
                    child.setSelected(selectAll);
                }
                refreshCounts.run();
                syncParentFromCounts.run();
            } finally {
                syncing.set(false);
            }
        });

        syncing.set(true);
        try {
            refreshCounts.run();
            syncParentFromCounts.run();
        } finally {
            syncing.set(false);
        }
    }

    private static void wireGroup(
            ExportFieldCatalogPanel.SectionGroup group,
            List<ExportFieldCatalogPanel.SectionGroup> rootGroups,
            AtomicBoolean syncing,
            Runnable refreshAll) {
        for (JCheckBox child : group.directChildren) {
            child.addItemListener(e -> refreshTreeWhenIdle(syncing, refreshAll));
            child.addPropertyChangeListener("enabled", e -> refreshTreeWhenIdle(syncing, refreshAll));
        }
        for (ExportFieldCatalogPanel.SectionGroup childGroup : group.childSections) {
            wireGroup(childGroup, rootGroups, syncing, refreshAll);
        }
        group.parent.addActionListener(e -> {
            if (syncing.get()) {
                return;
            }
            syncing.set(true);
            try {
                boolean selectAll = group.parent.getState() != TriStateCheckBox.State.DESELECTED;
                setDescendantLeavesSelected(group, selectAll);
                for (ExportFieldCatalogPanel.SectionGroup rootGroup : rootGroups) {
                    refreshGroupState(rootGroup);
                }
            } finally {
                syncing.set(false);
            }
        });
        group.parent.addPropertyChangeListener("enabled", e -> refreshTreeWhenIdle(syncing, refreshAll));
    }

    private static void refreshTreeWhenIdle(AtomicBoolean syncing, Runnable refreshAll) {
        if (syncing.get()) {
            return;
        }
        syncing.set(true);
        try {
            refreshAll.run();
        } finally {
            syncing.set(false);
        }
    }

    private static Counts refreshGroupState(ExportFieldCatalogPanel.SectionGroup group) {
        Counts counts = new Counts();
        for (JCheckBox child : group.directChildren) {
            counts.add(child);
        }
        for (ExportFieldCatalogPanel.SectionGroup childGroup : group.childSections) {
            counts.add(refreshGroupState(childGroup));
        }
        group.parent.setState(stateFor(counts));
        return counts;
    }

    private static TriStateCheckBox.State stateFor(Counts counts) {
        if (counts.enabled == 0 || counts.selected == 0) {
            return TriStateCheckBox.State.DESELECTED;
        }
        if (counts.selected == counts.enabled) {
            return TriStateCheckBox.State.SELECTED;
        }
        return TriStateCheckBox.State.INDETERMINATE;
    }

    private static void setDescendantLeavesSelected(ExportFieldCatalogPanel.SectionGroup group, boolean selected) {
        for (JCheckBox child : group.directChildren) {
            if (child.isEnabled()) {
                child.setSelected(selected);
            }
        }
        for (ExportFieldCatalogPanel.SectionGroup childGroup : group.childSections) {
            setDescendantLeavesSelected(childGroup, selected);
        }
    }

    private static final class Counts {
        private int enabled;
        private int selected;

        void add(JCheckBox child) {
            if (!child.isEnabled()) {
                return;
            }
            enabled++;
            if (child.isSelected()) {
                selected++;
            }
        }

        void add(Counts other) {
            enabled += other.enabled;
            selected += other.selected;
        }
    }
}
