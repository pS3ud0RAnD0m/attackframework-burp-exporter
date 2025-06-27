package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.utils.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class ConfigPanel extends JPanel {

    private final JRadioButton allTrafficRadio = new JRadioButton("All Traffic", true);
    private final JRadioButton inScopeRadio = new JRadioButton("In-Scope Traffic");
    private final JRadioButton customScopeRadio = new JRadioButton("Custom Scope (RegEx)");
    private final JTextField customScopeField = new JTextField("^.*acme\\.com$", 20);

    private final JCheckBox sitemapCheckbox = new JCheckBox("Sitemap", true);
    private final JCheckBox issuesCheckbox = new JCheckBox("Issues", true);
    private final JCheckBox trafficCheckbox = new JCheckBox("Scoped Traffic", true);

    private final JCheckBox fileSinkCheckbox = new JCheckBox("File", true);
    private final JTextField filePathField = new JTextField("/path/to/attackvectors.json", 20);
    private final JButton testWriteAccessButton = new JButton("Test Write Access");
    private final JLabel testWriteAccessStatus = new JLabel("");
    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", true);
    private final JTextField openSearchUrlField = new JTextField("http://localhost:9200", 20);
    private final JButton testConnectionButton = new JButton("Test Connection");
    private final JLabel testConnectionStatus = new JLabel("");

    public ConfigPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        add(buildScopePanel());
        add(Box.createVerticalStrut(10));
        add(buildSourcesPanel());
        add(Box.createVerticalStrut(10));
        add(buildSinksPanel());
        add(Box.createVerticalStrut(10));
        add(buildSaveButton());
    }

    private JPanel buildScopePanel() {
        JPanel scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.Y_AXIS));
        scopePanel.setBorder(BorderFactory.createTitledBorder("Scope"));

        ButtonGroup group = new ButtonGroup();
        group.add(inScopeRadio);
        group.add(customScopeRadio);
        group.add(allTrafficRadio);

        scopePanel.add(wrapLeftAligned(inScopeRadio));

        JPanel customScopeRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        customScopeRow.add(customScopeRadio);
        customScopeRow.add(customScopeField);
        scopePanel.add(customScopeRow);

        scopePanel.add(wrapLeftAligned(allTrafficRadio));

        return scopePanel;
    }

    private JPanel buildSourcesPanel() {
        JPanel sourcesPanel = new JPanel();
        sourcesPanel.setLayout(new BoxLayout(sourcesPanel, BoxLayout.Y_AXIS));
        sourcesPanel.setBorder(BorderFactory.createTitledBorder("Data Sources"));

        sourcesPanel.add(wrapLeftAligned(sitemapCheckbox));
        sourcesPanel.add(wrapLeftAligned(issuesCheckbox));
        sourcesPanel.add(wrapLeftAligned(trafficCheckbox));

        return sourcesPanel;
    }

    private JPanel buildSinksPanel() {
        JPanel sinksPanel = new JPanel();
        sinksPanel.setLayout(new BoxLayout(sinksPanel, BoxLayout.Y_AXIS));
        sinksPanel.setBorder(BorderFactory.createTitledBorder("Data Sinks"));

        JPanel fileRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileRow.add(fileSinkCheckbox);
        fileRow.add(filePathField);
        fileRow.add(testWriteAccessButton);
        fileRow.add(testWriteAccessStatus);

        testWriteAccessButton.addActionListener(e -> testWriteAccessStatus.setText("Testing write access ..."));

        sinksPanel.add(fileRow);

        JPanel openSearchRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        openSearchRow.add(openSearchSinkCheckbox);
        openSearchRow.add(openSearchUrlField);
        openSearchRow.add(testConnectionButton);
        openSearchRow.add(testConnectionStatus);

        testConnectionButton.addActionListener(e -> testConnectionStatus.setText("Testing connection ..."));

        sinksPanel.add(openSearchRow);

        return sinksPanel;
    }

    private JPanel buildSaveButton() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton saveButton = new JButton("Save");

        saveButton.addActionListener(new SaveButtonListener());
        panel.add(saveButton);
        return panel;
    }

    private JPanel wrapLeftAligned(JComponent comp) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.add(comp);
        return panel;
    }

    private class SaveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            List<String> selectedSources = new ArrayList<>();
            if (sitemapCheckbox.isSelected()) selectedSources.add("Sitemap");
            if (issuesCheckbox.isSelected()) selectedSources.add("Issues");
            if (trafficCheckbox.isSelected()) selectedSources.add("Scoped Traffic");

            List<String> selectedSinks = new ArrayList<>();
            if (fileSinkCheckbox.isSelected()) selectedSinks.add("File");
            if (openSearchSinkCheckbox.isSelected()) selectedSinks.add("OpenSearch");

            String scope = allTrafficRadio.isSelected() ? "All Traffic"
                    : inScopeRadio.isSelected() ? "In-Scope Traffic"
                    : "Custom: " + customScopeField.getText();

            Logger.logInfo("Scope selected: " + scope);
            Logger.logInfo("Sources selected: " + String.join(", ", selectedSources));
            Logger.logInfo("Sinks selected: " + String.join(", ", selectedSinks));
            Logger.logInfo("OpenSearch URL: " + openSearchUrlField.getText());
        }
    }
}
