package ai.attackframework.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.MultipleGradientPaint.CycleMethod;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.event.ActionListener;
import java.awt.geom.Ellipse2D;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import ai.attackframework.tools.burp.ui.primitives.ButtonStyles;
import ai.attackframework.tools.burp.ui.text.Tooltips;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import net.miginfocom.swing.MigLayout;

/**
 * Config Control section: Import / Export / Save actions, Start/Stop export, and their status rows.
 *
 * <p><strong>Responsibilities:</strong> render control panel and expose the assembled panel.
 * Callers supply actions and a status configurator for consistent text-area setup. A single
 * Start/Stop button toggles {@link RuntimeConfig#setExportRunning(boolean)}; its label and
 * tooltip show "Start" when stopped and "Stop" when running. The indicator shows starting
 * (yellow), running (green), or stopped (red).</p>
 *
 * <p><strong>Threading:</strong> created/used on the EDT. {@link #build()} mounts status text areas
 * into their wrapper panels so callers can update them via
 * {@link ai.attackframework.tools.burp.ui.primitives.StatusViews#setStatus(javax.swing.JTextArea,
 * javax.swing.JPanel, String, int, int)}.</p>
 */
public final class ConfigControlPanel {

    private static final Color INDICATOR_GREEN = new Color(0x00_88_00);
    private static final Color INDICATOR_YELLOW = new Color(0xCC_AA_00);
    private static final Color INDICATOR_RED   = new Color(0x99_00_00);
    private static final Color INDICATOR_BORDER = Color.BLACK;
    /** Inset so the border is not clipped by the component bounds. */
    private static final int INDICATOR_INSET   = 2;
    private static final int BUTTON_ROWS_EXTRA_GAP = 8;

    /** Paints a 3D-style circle: red/green fill with top-left gloss and a thin black border; transparent background. */
    private static final class IndicatorDot extends JComponent {
        private final int size;
        private State state = State.STOPPED;

        private enum State {
            STOPPED,
            STARTING,
            RUNNING
        }

        IndicatorDot(int sizePx) {
            this.size = sizePx;
            setPreferredSize(new Dimension(sizePx, sizePx));
            setMinimumSize(new Dimension(sizePx, sizePx));
            setMaximumSize(new Dimension(sizePx, sizePx));
            setName("control.exportIndicator");
            setOpaque(false);
            putClientProperty("html.disable", Boolean.FALSE);
        }

        @Override
        public javax.swing.JToolTip createToolTip() {
            return Tooltips.createHtmlToolTip(this);
        }

        void setState(State state) {
            if (this.state != state) {
                Logger.logTrace("[Control] indicator state=" + state.name().toLowerCase());
                this.state = state;
                repaint();
            }
            Tooltips.apply(this, Tooltips.html(switch (state) {
                case STOPPED -> "Export is stopped";
                case STARTING -> "Export is starting";
                case RUNNING -> "Export is running";
            }));
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int inset = INDICATOR_INSET;
            double d = size - 2.0 * inset;
            Ellipse2D.Double circle = new Ellipse2D.Double(inset, inset, d, d);

            Color base = switch (state) {
                case STOPPED -> INDICATOR_RED;
                case STARTING -> INDICATOR_YELLOW;
                case RUNNING -> INDICATOR_GREEN;
            };
            g2.setColor(base);
            g2.fill(circle);

            double cx = inset + d * 0.28;
            double cy = inset + d * 0.28;
            float radius = (float) (d * 0.65);
            float[] fractions = { 0f, 1f };
            Color[] colors = { new Color(255, 255, 255, 180), new Color(255, 255, 255, 0) };
            RadialGradientPaint gloss = new RadialGradientPaint(
                    (float) cx, (float) cy, radius, fractions, colors, CycleMethod.NO_CYCLE);
            g2.setPaint(gloss);
            g2.fill(circle);

            g2.setPaint(INDICATOR_BORDER);
            g2.setStroke(new BasicStroke(1f));
            g2.draw(circle);
            g2.dispose();
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
    /** Receives UI callbacks to complete or revert startup state after bootstrap. */
    private final Consumer<StartUiCallbacks> startAction;
    private final Runnable stopAction;

    public record StartUiCallbacks(Runnable onStartFailure, Runnable onStartSuccess) {}

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
            Consumer<StartUiCallbacks> startAction,
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

    /** Builds and returns the Config Control panel. */
    public JPanel build() {
        JPanel root = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        root.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Config Control",
                Tooltips.html("Import, export, save and apply the configuration.", "Start or stop Burp Exporter."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        root.add(header, "gapbottom 6");

        JButton importBtn = new Tooltips.HtmlButton("Import Config");
        JButton exportBtn = new Tooltips.HtmlButton("Export Config");
        JButton saveBtn = new Tooltips.HtmlButton("Save");
        saveBtn.setName("control.save");

        JButton startStopBtn = new Tooltips.HtmlButton(runningButtonLabel(RuntimeConfig.isExportRunning()));
        startStopBtn.setName("control.startStop");
        ButtonStyles.normalize(importBtn);
        ButtonStyles.normalize(exportBtn);
        ButtonStyles.normalize(saveBtn);
        ButtonStyles.normalize(startStopBtn);
        updateStartStopButton(startStopBtn, RuntimeConfig.isExportRunning());

        int btnHeight = startStopBtn.getPreferredSize().height;
        IndicatorDot indicator = new IndicatorDot(btnHeight);
        indicator.setState(RuntimeConfig.isExportRunning() ? IndicatorDot.State.RUNNING : IndicatorDot.State.STOPPED);

        assignToolTips(importBtn, exportBtn, saveBtn);

        importBtn.addActionListener(e -> importAction.run());
        exportBtn.addActionListener(e -> exportAction.run());
        saveBtn.addActionListener(saveAction);
        startStopBtn.addActionListener(e -> {
            boolean wasRunning = RuntimeConfig.isExportRunning();
            Logger.logDebug("[Control] " + (wasRunning ? "Stop" : "Start") + " clicked; running=" + wasRunning + " -> " + !wasRunning);
            if (wasRunning) {
                stopAction.run();
                updateStartStopButton(startStopBtn, false);
                indicator.setState(IndicatorDot.State.STOPPED);
            } else {
                RuntimeConfig.setExportRunning(true);
                RuntimeConfig.setExportStarting(true);
                updateStartStopButton(startStopBtn, true);
                indicator.setState(IndicatorDot.State.STARTING);
                updateControlStatus("Starting ...");
                Runnable revertUi = () -> {
                    RuntimeConfig.setExportRunning(false);
                    updateStartStopButton(startStopBtn, false);
                    indicator.setState(IndicatorDot.State.STOPPED);
                };
                Runnable markStartedUi = () -> {
                    RuntimeConfig.setExportStarting(false);
                    updateStartStopButton(startStopBtn, true);
                    indicator.setState(IndicatorDot.State.RUNNING);
                    updateControlStatus("Started");
                };
                SwingUtilities.invokeLater(() -> startAction.accept(new StartUiCallbacks(revertUi, markStartedUi)));
            }
        });

        JPanel row1 = new JPanel(new MigLayout("insets 0, gapx 10", "[left][left]", "[]"));
        row1.setAlignmentX(Component.LEFT_ALIGNMENT);
        row1.add(importBtn, "gapleft " + indent);
        row1.add(exportBtn);

        JPanel row2 = new JPanel(new MigLayout("insets 0, gapx 10", "[left][left][left]", "[]"));
        row2.setAlignmentX(Component.LEFT_ALIGNMENT);
        row2.add(saveBtn, "gapleft " + indent + ", aligny center");
        row2.add(startStopBtn, "aligny center");
        row2.add(indicator, "aligny center");

        JPanel buttons = new JPanel(new MigLayout("insets 0, gapy " + rowGap, "[left]", "[]" + rowGap + " []"));
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttons.add(row1, "wrap");
        buttons.add(row2, "gaptop " + BUTTON_ROWS_EXTRA_GAP);

        root.add(buttons);

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

    private void updateControlStatus(String message) {
        ai.attackframework.tools.burp.ui.primitives.StatusViews.setStatus(
                controlStatus, controlStatusWrapper, message, 20, 120);
    }

    private static String runningButtonLabel(boolean running) {
        return running ? "Stop" : "Start";
    }

    private static void updateStartStopButton(JButton btn, boolean running) {
        btn.setText(runningButtonLabel(running));
        Tooltips.apply(btn, running
                ? Tooltips.html("Stop exporting.", "The saved configuration remains unchanged.")
                : Tooltips.html("Start exporting to the configured destination(s)."));
    }

    /**
     * Assigns tooltips for control buttons in a single place.
     *
     * @param importBtn import action button
     * @param exportBtn export action button
     * @param saveBtn   save action button
     */
    private static void assignToolTips(JButton importBtn, JButton exportBtn, JButton saveBtn) {
        Tooltips.apply(importBtn, Tooltips.html("Import configuration from file."));
        Tooltips.apply(exportBtn, Tooltips.html("Export configuration to file."));
        Tooltips.apply(saveBtn, Tooltips.html(
                "Save and apply the current configuration.",
                "Secrets are only stored within in-process memory."
        ));
    }
}
