package ai.attackframework.tools.burp.ui;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.ActionListener;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Builds the "Admin" section panel used by ConfigPanel.
 * Components are owned by ConfigPanel and injected to keep a single source of state.
 */
public record ConfigAdminPanel(
        JTextArea importExportStatus,
        JPanel importExportStatusWrapper,
        JTextArea adminStatus,
        JPanel adminStatusWrapper,
        int indentPx,
        int rowGap,
        Consumer<JTextArea> statusConfigurer,
        Runnable importCallback,
        Runnable exportCallback,
        ActionListener saveListener
) {
    private static final String GAPLEFT = "gapleft ";
    private static final String STATUS_WRAP = "hidemode 3, alignx left, w pref!, wrap";

    public ConfigAdminPanel {
        Objects.requireNonNull(importExportStatus, "importExportStatus");
        Objects.requireNonNull(importExportStatusWrapper, "importExportStatusWrapper");
        Objects.requireNonNull(adminStatus, "adminStatus");
        Objects.requireNonNull(adminStatusWrapper, "adminStatusWrapper");
        Objects.requireNonNull(statusConfigurer, "statusConfigurer");
        Objects.requireNonNull(importCallback, "importCallback");
        Objects.requireNonNull(exportCallback, "exportCallback");
        Objects.requireNonNull(saveListener, "saveListener");
    }

    /**
     * Returns a panel containing Import/Export controls, Save, and their status areas.
     * Layout matches the original implementation for visual and test consistency.
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]", "[]" + rowGap + "[]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Admin");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        // Import/Export row
        JPanel importExportRow = new JPanel(new MigLayout("insets 0", "[]15[]15[left, grow]", ""));
        JButton importButton = new JButton("Import Config");
        JButton exportButton = new JButton("Export Config");
        importButton.addActionListener(e -> importCallback.run());
        exportButton.addActionListener(e -> exportCallback.run());
        importExportRow.add(importButton);
        importExportRow.add(exportButton);

        statusConfigurer.accept(importExportStatus);
        importExportStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        importExportStatusWrapper.removeAll();
        importExportStatusWrapper.add(importExportStatus, "w pref!");
        importExportStatusWrapper.setVisible(false);
        importExportRow.add(importExportStatusWrapper, STATUS_WRAP);

        panel.add(importExportRow, GAPLEFT + indentPx + ", wrap");

        // Save row
        JPanel saveRow = new JPanel(new MigLayout("insets 0", "[]", ""));
        JButton saveButton = new JButton("Save");
        saveButton.setToolTipText("Save and apply current config");
        saveButton.addActionListener(saveListener);
        saveRow.add(saveButton);

        statusConfigurer.accept(adminStatus);
        adminStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        adminStatusWrapper.removeAll();
        adminStatusWrapper.add(adminStatus, "w pref!");
        adminStatusWrapper.setVisible(false);
        saveRow.add(adminStatusWrapper, STATUS_WRAP);

        panel.add(saveRow, GAPLEFT + indentPx);

        return panel;
    }
}
