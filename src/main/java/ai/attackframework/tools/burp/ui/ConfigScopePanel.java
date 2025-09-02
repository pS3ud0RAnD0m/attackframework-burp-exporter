package ai.attackframework.tools.burp.ui;

import net.miginfocom.swing.MigLayout;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Component;
import java.awt.Font;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Builds the "Scope" section panel used by ConfigPanel.
 * State is owned by ConfigPanel and injected here for layout.
 */
public record ConfigScopePanel(
        JRadioButton allRadio,
        JRadioButton burpSuiteRadio,
        JRadioButton customRadio,
        JTextField customScopeField,
        JCheckBox customScopeRegexToggle,
        JButton addCustomScopeButton,
        JPanel customScopesContainer,
        List<JTextField> customScopeFields,
        List<JCheckBox> customScopeRegexToggles,
        List<JLabel> customScopeIndicators,
        int indentPx,
        Runnable updateCustomRegexFeedback,
        Runnable adjustScopeFieldWidths,
        Runnable addCustomScopeFieldRowCallback,
        Supplier<String> scopeColsSupplier,
        Consumer<JLabel> indicatorSizer
) {
    private static final String GAPLEFT = "gapleft ";

    public ConfigScopePanel {
        Objects.requireNonNull(allRadio, "allRadio");
        Objects.requireNonNull(burpSuiteRadio, "burpSuiteRadio");
        Objects.requireNonNull(customRadio, "customRadio");
        Objects.requireNonNull(customScopeField, "customScopeField");
        Objects.requireNonNull(customScopeRegexToggle, "customScopeRegexToggle");
        Objects.requireNonNull(addCustomScopeButton, "addCustomScopeButton");
        Objects.requireNonNull(customScopesContainer, "customScopesContainer");
        Objects.requireNonNull(customScopeFields, "customScopeFields");
        Objects.requireNonNull(customScopeRegexToggles, "customScopeRegexToggles");
        Objects.requireNonNull(customScopeIndicators, "customScopeIndicators");
        Objects.requireNonNull(updateCustomRegexFeedback, "updateCustomRegexFeedback");
        Objects.requireNonNull(adjustScopeFieldWidths, "adjustScopeFieldWidths");
        Objects.requireNonNull(addCustomScopeFieldRowCallback, "addCustomScopeFieldRowCallback");
        Objects.requireNonNull(scopeColsSupplier, "scopeColsSupplier");
        Objects.requireNonNull(indicatorSizer, "indicatorSizer");
    }

    /**
     * Returns the panel containing header, radios, and the initial custom-scope row.
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = new JLabel("Scope");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(burpSuiteRadio);
        scopeGroup.add(customRadio);
        scopeGroup.add(allRadio);

        panel.add(burpSuiteRadio, GAPLEFT + indentPx);

        customScopesContainer.removeAll();
        customScopesContainer.setLayout(new MigLayout("insets 0, wrap 1", "[grow]"));

        JLabel firstIndicator = new JLabel();
        firstIndicator.setName("scope.custom.regex.indicator.1");
        indicatorSizer.accept(firstIndicator);

        JPanel firstRow = new JPanel(new MigLayout("insets 0", scopeColsSupplier.get()));
        customScopeField.setName("scope.custom.regex");
        firstRow.add(customRadio);                                         // col 1
        firstRow.add(customScopeField, "growx");                 // col 2
        firstRow.add(customScopeRegexToggle, "split 2");         // col 3
        firstRow.add(firstIndicator);
        firstRow.add(addCustomScopeButton);                                // col 4
        customScopesContainer.add(firstRow, "growx, wrap");

        if (customScopeFields.isEmpty()) {
            customScopeFields.add(customScopeField);
            customScopeRegexToggles.add(customScopeRegexToggle);
            customScopeIndicators.add(firstIndicator);
        }

        panel.add(customScopesContainer, GAPLEFT + indentPx + ", growx");

        customScopeRegexToggle.addActionListener(e -> updateCustomRegexFeedback.run());

        DocumentListener dl = new DocumentListener() {
            private void onChange() {
                updateCustomRegexFeedback.run();
                adjustScopeFieldWidths.run();
            }
            @Override public void insertUpdate(DocumentEvent e) { onChange(); }
            @Override public void removeUpdate(DocumentEvent e) { onChange(); }
            @Override public void changedUpdate(DocumentEvent e) { onChange(); }
        };
        customScopeField.getDocument().addDocumentListener(dl);

        addCustomScopeButton.addActionListener(e -> addCustomScopeFieldRowCallback.run());

        panel.add(allRadio, GAPLEFT + indentPx);

        adjustScopeFieldWidths.run();

        return panel;
    }
}
