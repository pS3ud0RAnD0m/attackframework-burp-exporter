package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import ai.attackframework.tools.burp.ui.primitives.StatusViews;
import ai.attackframework.tools.burp.ui.text.Tooltips;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Destinations" section panel used by ConfigPanel.
 *
 * <p>Components are owned by {@link ConfigPanel} and injected to keep a single source of state.
 * The section has one shared status box, used for OpenSearch test-connection results.</p>
 */
public final class ConfigDestinationPanel {

    // Files destination
    private final JCheckBox fileSinkCheckbox;
    private final JTextField filePathField;
    private final AbstractButton fileJsonlCheckbox;
    private final AbstractButton fileBulkNdjsonCheckbox;
    private final JPanel fileLimitsPanel;
    // OpenSearch destination
    private final JCheckBox openSearchSinkCheckbox;
    private final JTextField openSearchUrlField;
    private final JPanel openSearchTlsPanel;
    private final JButton testConnectionButton;
    private final JPanel openSearchAuthFormPanel;
    private final JTextArea openSearchStatus;
    private final JPanel statusWrapper;

    // Layout
    private final int indentPx;
    private final int rowGap;

    // Delegate from ConfigPanel for consistent status styling
    private final Consumer<JTextArea> statusConfigurer;

    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";

    public ConfigDestinationPanel(
            JCheckBox fileSinkCheckbox,
            JTextField filePathField,
            AbstractButton fileJsonlCheckbox,
            AbstractButton fileBulkNdjsonCheckbox,
            JPanel fileLimitsPanel,
            JCheckBox openSearchSinkCheckbox,
            JTextField openSearchUrlField,
            JPanel openSearchTlsPanel,
            JButton testConnectionButton,
            JPanel openSearchAuthFormPanel,
            JTextArea openSearchStatus,
            JPanel statusWrapper,
            int indentPx,
            int rowGap,
            Consumer<JTextArea> statusConfigurer
    ) {
        this.fileSinkCheckbox = Objects.requireNonNull(fileSinkCheckbox, "fileSinkCheckbox");
        this.filePathField = Objects.requireNonNull(filePathField, "filePathField");
        this.fileJsonlCheckbox = Objects.requireNonNull(fileJsonlCheckbox, "fileJsonlCheckbox");
        this.fileBulkNdjsonCheckbox = Objects.requireNonNull(fileBulkNdjsonCheckbox, "fileBulkNdjsonCheckbox");
        this.fileLimitsPanel = Objects.requireNonNull(fileLimitsPanel, "fileLimitsPanel");

        this.openSearchSinkCheckbox = Objects.requireNonNull(openSearchSinkCheckbox, "openSearchSinkCheckbox");
        this.openSearchUrlField = Objects.requireNonNull(openSearchUrlField, "openSearchUrlField");
        this.openSearchTlsPanel = Objects.requireNonNull(openSearchTlsPanel, "openSearchTlsPanel");
        this.testConnectionButton = Objects.requireNonNull(testConnectionButton, "testConnectionButton");
        this.openSearchAuthFormPanel = Objects.requireNonNull(openSearchAuthFormPanel, "openSearchAuthFormPanel");
        this.openSearchStatus = Objects.requireNonNull(openSearchStatus, "openSearchStatus");
        this.statusWrapper = Objects.requireNonNull(statusWrapper, "statusWrapper");

        this.indentPx = indentPx;
        this.rowGap = rowGap;
        this.statusConfigurer = Objects.requireNonNull(statusConfigurer, "statusConfigurer");
    }

    /**
     * Builds the Destination section containing Files and OpenSearch controls.
     *
     * <p>Caller must invoke on the EDT. Layout keeps all Files controls on one row and places the
     * shared destination status box beneath the OpenSearch row.</p>
     *
     * @return assembled panel with destination controls and the shared status area
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[grow]", "[]"+rowGap+"[]"+rowGap+"[]"+rowGap+"[]"+rowGap+"[]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Destinations",
                Tooltips.html("Configure export destination(s)."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        // Files row
        JPanel fileRow = new JPanel(new MigLayout("insets 0", "[150!, left]20[pref]18[pref]8[pref]8[pref]22[pref]12[pref]12[pref]"));
        fileRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel formatsLabel = Tooltips.label("Format:",
                Tooltips.html("Select the on-disk export format."));
        JLabel safetyLabel = Tooltips.label("Disk Usage Limits:",
                Tooltips.html("Configure file-export safety limits.", "These controls stop file export before the destination grows too large."));
        JSeparator formatsSafetySeparator = buildInlineVerticalSeparator();

        fileRow.add(fileSinkCheckbox, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);
        fileRow.add(filePathField,    ALIGN_LEFT_TOP);
        fileRow.add(formatsLabel, ALIGN_LEFT_TOP);
        fileRow.add(fileJsonlCheckbox, ALIGN_LEFT_TOP);
        fileRow.add(fileBulkNdjsonCheckbox, "gapright 6, " + ALIGN_LEFT_TOP);
        fileRow.add(formatsSafetySeparator, "growy, h 18!, " + ALIGN_LEFT_TOP);
        fileRow.add(safetyLabel, ALIGN_LEFT_TOP);
        fileRow.add(fileLimitsPanel, ALIGN_LEFT_TOP);
        panel.add(fileRow, "growx, wrap");

        // OpenSearch row: URL + auth/TLS controls inline, with test button at the end
        JPanel openSearchRow = new JPanel(new MigLayout("insets 0", "[150!, left]20[pref]14[pref]12[pref]16[pref]"));
        openSearchRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JSeparator tlsSeparator = buildInlineVerticalSeparator();

        openSearchRow.add(openSearchSinkCheckbox, GAPLEFT + indentPx + ", top");
        openSearchRow.add(openSearchUrlField,     ALIGN_LEFT_TOP);
        openSearchRow.add(openSearchAuthFormPanel, ALIGN_LEFT_TOP);
        openSearchRow.add(tlsSeparator, "growy, h 18!, " + ALIGN_LEFT_TOP);
        openSearchRow.add(openSearchTlsPanel, ALIGN_LEFT_TOP);
        openSearchRow.add(testConnectionButton, ALIGN_LEFT_TOP);

        panel.add(openSearchRow, "growx, wrap");

        // OpenSearch status (below the row), left-aligned with checkboxes
        statusConfigurer.accept(openSearchStatus);
        StatusViews.configureWrapper(statusWrapper, openSearchStatus);
        panel.add(statusWrapper, "gapleft " + indentPx + ", hidemode 3, alignx left, w pref!, wrap");

        return panel;
    }

    private static JSeparator buildInlineVerticalSeparator() {
        JSeparator separator = new JSeparator(SwingConstants.VERTICAL);
        separator.setPreferredSize(new Dimension(8, 18));
        separator.setMinimumSize(new Dimension(8, 18));
        return separator;
    }
}
