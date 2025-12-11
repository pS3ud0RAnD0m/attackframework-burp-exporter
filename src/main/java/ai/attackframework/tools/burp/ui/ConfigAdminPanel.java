package ai.attackframework.tools.burp.ui;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.ActionListener;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Admin section: Import / Export / Save actions and their status rows.
 *
 * <p><strong>Responsibilities:</strong> render admin controls and expose the assembled panel.
 * Callers supply actions and a status configurator for consistent text-area setup.</p>
 *
 * <p><strong>Threading:</strong> created/used on the EDT. {@link #build()} mounts status text areas
 * into their wrapper panels so callers can update them via
 * {@link ai.attackframework.tools.burp.ui.primitives.StatusViews#setStatus(javax.swing.JTextArea,
 * javax.swing.JPanel, String, int, int)}.</p>
 */
public final class ConfigAdminPanel {

    private final JTextArea importExportStatus;
    private final JPanel importExportStatusWrapper;
    private final JTextArea adminStatus;
    private final JPanel adminStatusWrapper;
    private final int indent;
    private final int rowGap;
    private final Consumer<JTextArea> statusConfigurator;
    private final Runnable importAction;
    private final Runnable exportAction;
    private final ActionListener saveAction;

    /** Canonical constructor with null checks. */
    public ConfigAdminPanel(
            JTextArea importExportStatus,
            JPanel importExportStatusWrapper,
            JTextArea adminStatus,
            JPanel adminStatusWrapper,
            int indent,
            int rowGap,
            Consumer<JTextArea> statusConfigurator,
            Runnable importAction,
            Runnable exportAction,
            ActionListener saveAction
    ) {
        this.importExportStatus = Objects.requireNonNull(importExportStatus, "importExportStatus");
        this.importExportStatusWrapper = Objects.requireNonNull(importExportStatusWrapper, "importExportStatusWrapper");
        this.adminStatus = Objects.requireNonNull(adminStatus, "adminStatus");
        this.adminStatusWrapper = Objects.requireNonNull(adminStatusWrapper, "adminStatusWrapper");
        this.indent = indent;
        this.rowGap = rowGap;
        this.statusConfigurator = Objects.requireNonNull(statusConfigurator, "statusConfigurator");
        this.importAction = Objects.requireNonNull(importAction, "importAction");
        this.exportAction = Objects.requireNonNull(exportAction, "exportAction");
        this.saveAction = Objects.requireNonNull(saveAction, "saveAction");
    }

    /** Builds and returns the Admin panel. */
    public JPanel build() {
        JPanel root = new JPanel(new BorderLayout());

        // Controls row
        JPanel controls = new JPanel(new MigLayout(
                "insets 0, gapx 10, gapy " + rowGap,
                "[left]10[left]10[left]10[left]",
                "[]"
        ));

        JButton importBtn = new JButton("Import Config");
        JButton exportBtn = new JButton("Export Config");
        JButton saveBtn   = new JButton("Save");
        // Stable name for tests/tooling.
        saveBtn.setName("admin.save");

        assignToolTips(importBtn, exportBtn, saveBtn);

        importBtn.addActionListener(e -> importAction.run());
        exportBtn.addActionListener(e -> exportAction.run());
        saveBtn.addActionListener(saveAction);

        controls.add(importBtn, "gapleft " + indent);
        controls.add(exportBtn);
        controls.add(saveBtn);

        // Status rows (mirror ConfigSinksPanel styling: compact, bordered, pref-width areas)
        statusConfigurator.accept(importExportStatus);
        statusConfigurator.accept(adminStatus);

        importExportStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        importExportStatusWrapper.removeAll();
        importExportStatusWrapper.add(importExportStatus, "w pref!");
        importExportStatusWrapper.setVisible(false);

        adminStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        adminStatusWrapper.removeAll();
        adminStatusWrapper.add(adminStatus, "w pref!");
        adminStatusWrapper.setVisible(false);

        // Two rows: import/export status (row 1) and admin status (row 2) with a small vertical gap.
        final int gapPx = 8;
        JPanel statuses = new JPanel(new MigLayout(
                "insets " + rowGap + " " + indent + " 0 0, gapy " + gapPx,
                "[left]",
                "[] " + gapPx + " []"
        ));
        statuses.add(importExportStatusWrapper, "hidemode 3, w pref!, wrap");
        statuses.add(adminStatusWrapper, "hidemode 3, w pref!");

        root.add(controls, BorderLayout.NORTH);
        root.add(statuses, BorderLayout.CENTER);
        return root;
    }

    /**
     * Assigns tooltips for admin buttons in a single place.
     *
     * @param importBtn import action button
     * @param exportBtn export action button
     * @param saveBtn   save action button
     */
    private static void assignToolTips(JButton importBtn, JButton exportBtn, JButton saveBtn) {
        importBtn.setToolTipText("Import configuration from file");
        exportBtn.setToolTipText("Export configuration to file");
        saveBtn.setToolTipText("Save current configuration");
    }
}
