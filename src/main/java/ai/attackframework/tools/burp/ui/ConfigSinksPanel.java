package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.primitives.StatusViews;
import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Font;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Builds the "Data Sinks" section panel used by ConfigPanel.
 * Components are owned by ConfigPanel and injected to keep a single source of state.
 */
public record ConfigSinksPanel(
        // Files sink
        JCheckBox fileSinkCheckbox,
        JTextField filePathField,
        JButton createFilesButton,

        JTextArea fileStatus,
        JPanel fileStatusWrapper,

        // OpenSearch sink
        JCheckBox openSearchSinkCheckbox,
        JTextField openSearchUrlField,
        JButton testConnectionButton,
        JButton createIndexesButton,
        JTextArea openSearchStatus,
        JPanel statusWrapper,

        // Layout
        int indentPx,
        int rowGap,

        // Delegate from ConfigPanel for consistent status styling
        Consumer<JTextArea> statusConfigurer
) {
    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";

    public ConfigSinksPanel {
        Objects.requireNonNull(fileSinkCheckbox, "fileSinkCheckbox");
        Objects.requireNonNull(filePathField, "filePathField");
        Objects.requireNonNull(createFilesButton, "createFilesButton");
        Objects.requireNonNull(fileStatus, "fileStatus");
        Objects.requireNonNull(fileStatusWrapper, "fileStatusWrapper");

        Objects.requireNonNull(openSearchSinkCheckbox, "openSearchSinkCheckbox");
        Objects.requireNonNull(openSearchUrlField, "openSearchUrlField");
        Objects.requireNonNull(testConnectionButton, "testConnectionButton");
        Objects.requireNonNull(createIndexesButton, "createIndexesButton");
        Objects.requireNonNull(openSearchStatus, "openSearchStatus");
        Objects.requireNonNull(statusWrapper, "statusWrapper");

        Objects.requireNonNull(statusConfigurer, "statusConfigurer");
    }

    /**
     * Returns a panel that contains the header and the Files/OpenSearch rows.
     * Layout mirrors the original implementation for visual/test consistency.
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[grow]", "[]"+rowGap+"[]"+rowGap+"[]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sinks");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        // Files row
        JPanel fileRow = new JPanel(new MigLayout("insets 0", "[150!, left]20[pref]20[left]20[left, grow]"));
        fileRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        fileRow.add(fileSinkCheckbox, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);
        fileRow.add(filePathField,    ALIGN_LEFT_TOP);
        fileRow.add(createFilesButton, ALIGN_LEFT_TOP);

        statusConfigurer.accept(fileStatus);
        StatusViews.configureWrapper(fileStatusWrapper, fileStatus);
        fileRow.add(fileStatusWrapper, "hidemode 3, alignx left, w pref!, wrap");
        panel.add(fileRow, "growx, wrap");

        // OpenSearch row
        JPanel openSearchRow = new JPanel(new MigLayout("insets 0", "[150!, left]20[pref]20[left]20[left, grow]"));
        openSearchRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        openSearchRow.add(openSearchSinkCheckbox, GAPLEFT + indentPx + ", top");
        openSearchRow.add(openSearchUrlField,     ALIGN_LEFT_TOP);
        openSearchRow.add(testConnectionButton,   "split 2, " + ALIGN_LEFT_TOP);
        openSearchRow.add(createIndexesButton,    "gapleft 15, " + ALIGN_LEFT_TOP);

        statusConfigurer.accept(openSearchStatus);
        StatusViews.configureWrapper(statusWrapper, openSearchStatus);
        openSearchRow.add(statusWrapper, "hidemode 3, alignx left, w pref!, wrap");
        panel.add(openSearchRow, "growx, wrap");

        return panel;
    }
}
