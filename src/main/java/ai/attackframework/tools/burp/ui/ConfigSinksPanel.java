package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import net.miginfocom.swing.MigLayout;

import ai.attackframework.tools.burp.ui.primitives.StatusViews;

/**
 * Builds the "Data Sinks" section panel used by ConfigPanel.
 * Components are owned by ConfigPanel and injected to keep a single source of state.
 */
public final class ConfigSinksPanel {

    // Files sink
    private final JCheckBox fileSinkCheckbox;
    private final JTextField filePathField;
    private final JButton createFilesButton;
    private final JTextArea fileStatus;
    private final JPanel fileStatusWrapper;

    // OpenSearch sink
    private final JCheckBox openSearchSinkCheckbox;
    private final JTextField openSearchUrlField;
    private final JButton testConnectionButton;
    private final JButton createIndexesButton;
    private final JTextArea openSearchStatus;
    private final JPanel statusWrapper;

    // Layout
    private final int indentPx;
    private final int rowGap;

    // Delegate from ConfigPanel for consistent status styling
    private final Consumer<JTextArea> statusConfigurer;

    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";

    public ConfigSinksPanel(
            JCheckBox fileSinkCheckbox,
            JTextField filePathField,
            JButton createFilesButton,
            JTextArea fileStatus,
            JPanel fileStatusWrapper,
            JCheckBox openSearchSinkCheckbox,
            JTextField openSearchUrlField,
            JButton testConnectionButton,
            JButton createIndexesButton,
            JTextArea openSearchStatus,
            JPanel statusWrapper,
            int indentPx,
            int rowGap,
            Consumer<JTextArea> statusConfigurer
    ) {
        this.fileSinkCheckbox = Objects.requireNonNull(fileSinkCheckbox, "fileSinkCheckbox");
        this.filePathField = Objects.requireNonNull(filePathField, "filePathField");
        this.createFilesButton = Objects.requireNonNull(createFilesButton, "createFilesButton");
        this.fileStatus = Objects.requireNonNull(fileStatus, "fileStatus");
        this.fileStatusWrapper = Objects.requireNonNull(fileStatusWrapper, "fileStatusWrapper");

        this.openSearchSinkCheckbox = Objects.requireNonNull(openSearchSinkCheckbox, "openSearchSinkCheckbox");
        this.openSearchUrlField = Objects.requireNonNull(openSearchUrlField, "openSearchUrlField");
        this.testConnectionButton = Objects.requireNonNull(testConnectionButton, "testConnectionButton");
        this.createIndexesButton = Objects.requireNonNull(createIndexesButton, "createIndexesButton");
        this.openSearchStatus = Objects.requireNonNull(openSearchStatus, "openSearchStatus");
        this.statusWrapper = Objects.requireNonNull(statusWrapper, "statusWrapper");

        this.indentPx = indentPx;
        this.rowGap = rowGap;
        this.statusConfigurer = Objects.requireNonNull(statusConfigurer, "statusConfigurer");
    }

    /**
     * Builds the Data Sinks section containing Files and OpenSearch controls.
     * <p>
     * Caller must invoke on the EDT. Layout mirrors the original for test/visual consistency
     * and applies common status configuration to both sink wrappers.</p>
     * <p>
     * @return assembled panel with sink controls and status areas
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
