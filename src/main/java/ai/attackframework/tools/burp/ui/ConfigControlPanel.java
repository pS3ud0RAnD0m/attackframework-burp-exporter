package ai.attackframework.tools.burp.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.event.ActionListener;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import net.miginfocom.swing.MigLayout;

/**
 * Control section: Import / Export / Save actions, Start/Stop export, and their status rows.
 *
 * <p><strong>Responsibilities:</strong> render control panel and expose the assembled panel.
 * Callers supply actions and a status configurator for consistent text-area setup. A single
 * Start/Stop button toggles {@link RuntimeConfig#setExportRunning(boolean)}; its label and
 * tooltip show "Start" when stopped and "Stop" when running. The indicator shows running
 * (green) or stopped (red).</p>
 *
 * <p><strong>Threading:</strong> created/used on the EDT. {@link #build()} mounts status text areas
 * into their wrapper panels so callers can update them via
 * {@link ai.attackframework.tools.burp.ui.primitives.StatusViews#setStatus(javax.swing.JTextArea,
 * javax.swing.JPanel, String, int, int)}.</p>
 */
public final class ConfigControlPanel {

    private static final Color INDICATOR_GREEN = new Color(0x00_88_00);
    private static final Color INDICATOR_RED   = new Color(0xCC_00_00);

    /** Paints a circle at exact pixel size so it matches button height and aligns. */
    private static final class IndicatorDot extends JComponent {
        private final int size;
        private boolean running;

        IndicatorDot(int sizePx) {
            this.size = sizePx;
            setPreferredSize(new Dimension(sizePx, sizePx));
            setMinimumSize(new Dimension(sizePx, sizePx));
            setMaximumSize(new Dimension(sizePx, sizePx));
            setName("control.exportIndicator");
        }

        void setRunning(boolean running) {
            if (this.running != running) {
                this.running = running;
                repaint();
            }
            setToolTipText(running ? "Export is running" : "Export is stopped");
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            int pad = Math.max(1, size / 8);
            int d = size - 2 * pad;
            g.setColor(running ? INDICATOR_GREEN : INDICATOR_RED);
            g.fillOval(pad, pad, d, d);
        }
    }

    private final JTextArea importExportStatus;
    private final JPanel importExportStatusWrapper;
    private final JTextArea controlStatus;
    private final JPanel controlStatusWrapper;
    private final int indent;
    private final int rowGap;
    private final Consumer<JTextArea> statusConfigurator;
    private final Runnable importAction;
    private final Runnable exportAction;
    private final ActionListener saveAction;
    private final Runnable startAction;
    private final Runnable stopAction;

    /** Canonical constructor with null checks. */
    public ConfigControlPanel(
            JTextArea importExportStatus,
            JPanel importExportStatusWrapper,
            JTextArea controlStatus,
            JPanel controlStatusWrapper,
            int indent,
            int rowGap,
            Consumer<JTextArea> statusConfigurator,
            Runnable importAction,
            Runnable exportAction,
            ActionListener saveAction,
            Runnable startAction,
            Runnable stopAction
    ) {
        this.importExportStatus = Objects.requireNonNull(importExportStatus, "importExportStatus");
        this.importExportStatusWrapper = Objects.requireNonNull(importExportStatusWrapper, "importExportStatusWrapper");
        this.controlStatus = Objects.requireNonNull(controlStatus, "controlStatus");
        this.controlStatusWrapper = Objects.requireNonNull(controlStatusWrapper, "controlStatusWrapper");
        this.indent = indent;
        this.rowGap = rowGap;
        this.statusConfigurator = Objects.requireNonNull(statusConfigurator, "statusConfigurator");
        this.importAction = Objects.requireNonNull(importAction, "importAction");
        this.exportAction = Objects.requireNonNull(exportAction, "exportAction");
        this.saveAction = Objects.requireNonNull(saveAction, "saveAction");
        this.startAction = Objects.requireNonNull(startAction, "startAction");
        this.stopAction = Objects.requireNonNull(stopAction, "stopAction");
    }

    /** Builds and returns the Control panel. */
    public JPanel build() {
        JPanel root = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        root.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Control");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        root.add(header, "gapbottom 6");

        JButton importBtn = new JButton("Import Config");
        JButton exportBtn = new JButton("Export Config");
        JButton saveBtn   = new JButton("Save");
        saveBtn.setName("control.save");

        JButton startStopBtn = new JButton(runningButtonLabel(RuntimeConfig.isExportRunning()));
        startStopBtn.setName("control.startStop");
        updateStartStopButton(startStopBtn, RuntimeConfig.isExportRunning());

        int btnHeight = startStopBtn.getPreferredSize().height;
        IndicatorDot indicator = new IndicatorDot(btnHeight);
        indicator.setRunning(RuntimeConfig.isExportRunning());

        assignToolTips(importBtn, exportBtn, saveBtn);

        importBtn.addActionListener(e -> importAction.run());
        exportBtn.addActionListener(e -> exportAction.run());
        saveBtn.addActionListener(saveAction);
        startStopBtn.addActionListener(e -> {
            boolean wasRunning = RuntimeConfig.isExportRunning();
            if (wasRunning) {
                stopAction.run();
                updateStartStopButton(startStopBtn, false);
                indicator.setRunning(false);
            } else {
                startAction.run();
                updateStartStopButton(startStopBtn, true);
                indicator.setRunning(true);
            }
        });

        // Row 1: Import Config, Export Config
        JPanel row1 = new JPanel(new MigLayout("insets 0, gapx 10", "[left][left]", "[]"));
        row1.setAlignmentX(Component.LEFT_ALIGNMENT);
        row1.add(importBtn, "gapleft " + indent);
        row1.add(exportBtn);

        // Row 2: Save, Start/Stop, indicator. Indicator is a painted circle same height as buttons; aligny center.
        JPanel row2 = new JPanel(new MigLayout("insets 0, gapx 10", "[left][left][left]", "[]"));
        row2.setAlignmentX(Component.LEFT_ALIGNMENT);
        row2.add(saveBtn, "gapleft " + indent + ", aligny center");
        row2.add(startStopBtn, "aligny center");
        row2.add(indicator, "aligny center");

        final int buttonRowGap = 10;
        JPanel buttons = new JPanel(new MigLayout("insets 0, gapy " + buttonRowGap, "[left]", "[]" + buttonRowGap + " []"));
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttons.add(row1, "wrap");
        buttons.add(row2);

        root.add(buttons);

        // Status rows (mirror ConfigSinksPanel styling: compact, bordered, pref-width areas)
        statusConfigurator.accept(importExportStatus);
        statusConfigurator.accept(controlStatus);

        importExportStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        importExportStatusWrapper.removeAll();
        importExportStatusWrapper.add(importExportStatus, "w pref!");
        importExportStatusWrapper.setVisible(false);

        controlStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        controlStatusWrapper.removeAll();
        controlStatusWrapper.add(controlStatus, "w pref!");
        controlStatusWrapper.setVisible(false);

        final int gapPx = 8;
        JPanel statuses = new JPanel(new MigLayout(
                "insets " + rowGap + " " + indent + " 0 0, gapy " + gapPx,
                "[left]",
                "[] " + gapPx + " []"
        ));
        statuses.add(importExportStatusWrapper, "hidemode 3, w pref!, wrap");
        statuses.add(controlStatusWrapper, "hidemode 3, w pref!");

        root.add(statuses);
        return root;
    }

    private static String runningButtonLabel(boolean running) {
        return running ? "Stop" : "Start";
    }

    private static void updateStartStopButton(JButton btn, boolean running) {
        btn.setText(runningButtonLabel(running));
        btn.setToolTipText(running
                ? "Stop exporting (configuration unchanged)"
                : "Start exporting to configured sinks");
    }

    /**
     * Assigns tooltips for control buttons in a single place.
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
