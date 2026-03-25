package ai.attackframework.tools.burp.ui.text;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.JToolTip;

/**
 * Shared tooltip helpers so panels use consistent formatting.
 */
public final class Tooltips {
    private static final String HTML_DISABLE = "html.disable";

    private Tooltips() {}

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
        public JToolTip createToolTip() {
            return createHtmlToolTip(this);
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
        if (cleanDescription.isEmpty()) {
            return cleanSource.isEmpty() ? null : htmlRaw("<b>Source:</b> " + escapeHtml(cleanSource));
        }
        if (cleanSource.isEmpty()) {
            return html(cleanDescription);
        }
        return htmlRaw(
                escapeHtml(cleanDescription),
                "<b>Source:</b> " + escapeHtml(cleanSource)
        );
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
}
