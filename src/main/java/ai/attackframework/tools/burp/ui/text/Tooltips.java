package ai.attackframework.tools.burp.ui.text;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;

/**
 * Shared tooltip helpers so panels use consistent formatting.
 */
public final class Tooltips {
    private static final String HTML_DISABLE = "html.disable";
    private static final String TOOLTIP_FORWARDER_KEY = Tooltips.class.getName() + ".tooltipForwarder";
    private static final int STRUCTURED_TOOLTIP_THRESHOLD = 120;

    private Tooltips() {}

    /**
     * Configures the shared Swing tooltip manager for hover-friendly behavior.
     *
     * <p>Tooltips appear immediately, reshow immediately when moving between related controls, and
     * stay visible while the cursor remains over the hover target.</p>
     */
    public static void configureSharedToolTipManager() {
        ToolTipManager manager = ToolTipManager.sharedInstance();
        manager.setInitialDelay(0);
        manager.setReshowDelay(0);
        manager.setDismissDelay(Integer.MAX_VALUE);
    }

    public static JToolTip createHtmlToolTip(JComponent owner) {
        JToolTip toolTip = new JToolTip();
        toolTip.putClientProperty(HTML_DISABLE, Boolean.FALSE);
        toolTip.setComponent(owner);
        return toolTip;
    }

    public static final class HtmlLabel extends JLabel {
        public HtmlLabel(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlLabel(String text, int horizontalAlignment) {
            super(text, horizontalAlignment);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    /**
     * {@link JPanel} variant whose {@link JToolTip} is configured to render HTML so callers can
     * pass tooltips produced by {@link #htmlRaw(String...)} / {@link #html(String...)}. Plain
     * {@code JPanel} produces a default {@code JToolTip} without the {@code html.disable=FALSE}
     * client property, which causes Swing to render HTML markup as literal text.
     */
    public static final class HtmlPanel extends JPanel {
        public HtmlPanel() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlPanel(java.awt.LayoutManager layout) {
            super(layout);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlButton extends JButton {
        public HtmlButton(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static class HtmlCheckBox extends JCheckBox {
        public HtmlCheckBox(String text, boolean selected) {
            super(text, selected);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlCheckBox(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlRadioButton extends JRadioButton {
        public HtmlRadioButton(String text) {
            super(text);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        public HtmlRadioButton(String text, boolean selected) {
            super(text, selected);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlTextField extends JTextField {
        public HtmlTextField() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlPasswordField extends JPasswordField {
        public HtmlPasswordField() {
            super();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }
    }

    public static final class HtmlComboBox<E> extends JComboBox<E> {
        public HtmlComboBox(E[] items) {
            super(items);
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
        }

        @Override
        public void addNotify() {
            super.addNotify();
            syncChildTooltips();
        }

        @Override
        public void updateUI() {
            super.updateUI();
            putClientProperty(HTML_DISABLE, Boolean.FALSE);
            syncChildTooltips();
        }

        @Override
        public void setToolTipText(String text) {
            super.setToolTipText(text);
            syncChildTooltips();
        }

        @Override
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
        }

        /**
         * Mirrors HTML tooltip ownership to child widgets such as the combo arrow button.
         *
         * <p>Swing copies tooltip text to combo children, but it does not copy this helper's HTML
         * client-property setup. Refresh after UI install and tooltip updates so every hover target
         * within the combo renders the same HTML tooltip.</p>
         */
        private void syncChildTooltips() {
            Runnable sync = () -> applyHtmlTooltipToChildren(this, this, getToolTipText());
            if (isDisplayable()) {
                SwingUtilities.invokeLater(sync);
            } else {
                sync.run();
            }
        }
    }

    public static <T extends JComponent> T apply(T component, String tooltip) {
        component.putClientProperty(HTML_DISABLE, Boolean.FALSE);
        component.setToolTipText(tooltip);
        return component;
    }

    public static JLabel label(String text, String tooltip) {
        return apply(new HtmlLabel(text), tooltip);
    }

    public static String html(String... lines) {
        String body = Arrays.stream(lines)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .map(Tooltips::escapeHtml)
                .collect(Collectors.joining("<br>"));
        return body.isEmpty() ? null : "<html>" + body + "</html>";
    }

    public static String htmlRaw(String... lines) {
        String body = Arrays.stream(lines)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .collect(Collectors.joining("<br>"));
        return body.isEmpty() ? null : "<html>" + body + "</html>";
    }

    public static String htmlWithSource(String description, String source) {
        String cleanDescription = description == null ? "" : description.trim();
        String cleanSource = source == null ? "" : source.trim();
        if (cleanDescription.isEmpty() && cleanSource.isEmpty()) {
            return null;
        }
        List<String> lines = new ArrayList<>();
        if (!cleanDescription.isEmpty()) {
            appendLabeledTooltipText(lines, "Description", cleanDescription);
        }
        if (!cleanSource.isEmpty()) {
            appendLabeledTooltipText(lines, "Source", cleanSource);
        }
        return htmlRaw(lines.toArray(String[]::new));
    }

    public static String textWithSource(String description, String source) {
        return htmlWithSource(description, source);
    }

    public static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private static void appendLabeledTooltipText(List<String> lines, String label, String text) {
        List<String> textLines = splitTooltipText(text);
        if (textLines.isEmpty()) {
            return;
        }
        if (textLines.size() == 1 && text.length() <= STRUCTURED_TOOLTIP_THRESHOLD) {
            lines.add("<b>" + label + ":</b> " + escapeHtml(textLines.getFirst()));
            return;
        }
        lines.add("<b>" + label + ":</b>");
        for (String line : textLines) {
            lines.add("&nbsp;&nbsp;" + escapeHtml(line));
        }
    }

    private static List<String> splitTooltipText(String text) {
        String normalized = text == null ? "" : text.trim();
        if (normalized.isEmpty()) {
            return List.of();
        }
        String[] parts = normalized.split("(?<=\\.)\\s+|;\\s+|\\r?\\n");
        List<String> lines = new ArrayList<>();
        for (String part : parts) {
            String trimmed = part == null ? "" : part.trim();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        return lines.isEmpty() ? List.of(normalized) : lines;
    }

    private static void applyHtmlTooltipToChildren(Container root, JComponent tooltipOwner, String tooltip) {
        for (Component child : root.getComponents()) {
            if (child instanceof JComponent jc) {
                jc.putClientProperty(HTML_DISABLE, Boolean.FALSE);
                if (jc instanceof JButton) {
                    installTooltipForwarder(jc, tooltipOwner);
                } else {
                    jc.setToolTipText(tooltip);
                }
            }
            if (child instanceof Container nested) {
                applyHtmlTooltipToChildren(nested, tooltipOwner, tooltip);
            }
        }
    }

    private static void installTooltipForwarder(JComponent child, JComponent tooltipOwner) {
        Object existing = child.getClientProperty(TOOLTIP_FORWARDER_KEY);
        if (existing instanceof ComboChildTooltipForwarder forwarder) {
            child.removeMouseListener(forwarder);
            child.removeMouseMotionListener(forwarder);
        }
        child.setToolTipText(null);
        ComboChildTooltipForwarder forwarder = new ComboChildTooltipForwarder(child, tooltipOwner);
        child.addMouseListener(forwarder);
        child.addMouseMotionListener(forwarder);
        child.putClientProperty(TOOLTIP_FORWARDER_KEY, forwarder);
    }

    /** Forwards combo-child hover events to the combo so the combo's HTML tooltip is used. */
    private static final class ComboChildTooltipForwarder extends MouseAdapter {
        private final JComponent source;
        private final JComponent tooltipOwner;

        private ComboChildTooltipForwarder(JComponent source, JComponent tooltipOwner) {
            this.source = source;
            this.tooltipOwner = tooltipOwner;
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            ToolTipManager.sharedInstance().mouseEntered(convert(e));
        }

        @Override
        public void mouseMoved(MouseEvent e) {
            ToolTipManager.sharedInstance().mouseMoved(convert(e));
        }

        @Override
        public void mouseExited(MouseEvent e) {
            ToolTipManager.sharedInstance().mouseExited(convert(e));
        }

        private MouseEvent convert(MouseEvent e) {
            return SwingUtilities.convertMouseEvent(source, e, tooltipOwner);
        }
    }
}
