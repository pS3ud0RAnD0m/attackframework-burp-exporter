package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.utils.Logger;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ConfigPanel extends JPanel {
    private final List<JCheckBox> sourceCheckboxes = new ArrayList<>();
    private final ButtonGroup scopeGroup = new ButtonGroup();

    public ConfigPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        add(buildScopeSection());
        add(buildSourceSection());
        add(buildSinkSection());
        add(buildSaveButton());
    }

    private JPanel buildScopeSection() {
        JPanel scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.Y_AXIS));
        scopePanel.setBorder(new TitledBorder("Scope"));

        JRadioButton inScope = new JRadioButton("In-Scope Traffic");
        JRadioButton customScope = new JRadioButton("Custom Scope (RegEx)");
        JRadioButton allTraffic = new JRadioButton("All Traffic");

        JTextField regexField = new JTextField("^.*acme\\.com$");
        regexField.setMaximumSize(new Dimension(300, 24));

        scopeGroup.add(inScope);
        scopeGroup.add(customScope);
        scopeGroup.add(allTraffic);

        scopePanel.add(inScope);

        JPanel customPanel = new JPanel();
        customPanel.setLayout(new BoxLayout(customPanel, BoxLayout.X_AXIS));
        customPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        customPanel.add(customScope);
        customPanel.add(Box.createRigidArea(new Dimension(10, 0)));
        customPanel.add(regexField);
        scopePanel.add(customPanel);

        scopePanel.add(allTraffic);
        inScope.setSelected(true);

        return scopePanel;
    }

    private JPanel buildSourceSection() {
        JPanel sourcePanel = new JPanel();
        sourcePanel.setLayout(new BoxLayout(sourcePanel, BoxLayout.Y_AXIS));
        sourcePanel.setBorder(new TitledBorder("Data Sources"));

        JCheckBox sitemap = new JCheckBox("Sitemap");
        JCheckBox issues = new JCheckBox("Issues");
        JCheckBox scoped = new JCheckBox("Scoped Traffic");

        sourceCheckboxes.add(sitemap);
        sourceCheckboxes.add(issues);
        sourceCheckboxes.add(scoped);

        sourcePanel.add(sitemap);
        sourcePanel.add(issues);
        sourcePanel.add(scoped);

        return sourcePanel;
    }

    private JPanel buildSinkSection() {
        JPanel sinkPanel = new JPanel();
        sinkPanel.setLayout(new BoxLayout(sinkPanel, BoxLayout.Y_AXIS));
        sinkPanel.setBorder(new TitledBorder("Data Sinks"));

        // OpenSearch row
        JPanel osPanel = new JPanel();
        osPanel.setLayout(new BoxLayout(osPanel, BoxLayout.X_AXIS));
        osPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JCheckBox openSearchCheckbox = new JCheckBox("OpenSearch");
        JLabel osLabel = new JLabel("URL:");
        JTextField osField = new JTextField("http://localhost:9200");
        osField.setMaximumSize(new Dimension(300, 24));
        JButton testConnection = new JButton("Test Connection");

        osPanel.add(openSearchCheckbox);
        osPanel.add(Box.createRigidArea(new Dimension(10, 0)));
        osPanel.add(osLabel);
        osPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        osPanel.add(osField);
        osPanel.add(Box.createRigidArea(new Dimension(10, 0)));
        osPanel.add(testConnection);

        testConnection.addActionListener(e ->
                Logger.logInfo("Testing OpenSearch connection: " + osField.getText())
        );

        // File row
        JPanel filePanel = new JPanel();
        filePanel.setLayout(new BoxLayout(filePanel, BoxLayout.X_AXIS));
        filePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JCheckBox fileCheckbox = new JCheckBox("File");
        JLabel fileLabel = new JLabel("Path:");
        JTextField fileField = new JTextField("/path/to/output.json");
        fileField.setMaximumSize(new Dimension(300, 24));
        JButton testWrite = new JButton("Test Write Access");

        filePanel.add(fileCheckbox);
        filePanel.add(Box.createRigidArea(new Dimension(10, 0)));
        filePanel.add(fileLabel);
        filePanel.add(Box.createRigidArea(new Dimension(5, 0)));
        filePanel.add(fileField);
        filePanel.add(Box.createRigidArea(new Dimension(10, 0)));
        filePanel.add(testWrite);

        testWrite.addActionListener(e ->
                Logger.logInfo("Testing write access to: " + fileField.getText())
        );

        sinkPanel.add(osPanel);
        sinkPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        sinkPanel.add(filePanel);

        return sinkPanel;
    }

    private JButton buildSaveButton() {
        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);

        saveButton.addActionListener(e -> {
            List<String> selectedSources = new ArrayList<>();
            for (JCheckBox cb : sourceCheckboxes) {
                if (cb.isSelected()) selectedSources.add(cb.getText());
            }

            Logger.logInfo("Sources selected: " + String.join(", ", selectedSources));
        });

        return saveButton;
    }
}
