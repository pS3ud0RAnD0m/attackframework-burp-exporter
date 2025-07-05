package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink;
import ai.attackframework.vectors.sources.burp.utils.Logger;
import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchClientWrapper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class ConfigPanel extends JPanel {

    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox = new JCheckBox("Sitemap", true);
    private final JCheckBox issuesCheckbox = new JCheckBox("Issues", true);
    private final JCheckBox trafficCheckbox = new JCheckBox("Traffic", true);

    private final JRadioButton allRadio = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio = new JRadioButton("Custom (RegEx)");
    private final JTextField customScopeField = new JTextField("^.*acme\\.com$", 20);

    private final JCheckBox fileSinkCheckbox = new JCheckBox("File", true);
    private final JTextField filePathField = new JTextField("/path/to/attackframework-burp.json", 20);
    private final JButton testWriteAccessButton = new JButton("Test Write Access");
    private final JLabel testWriteAccessStatus = new JLabel("");
    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    private final JTextField openSearchUrlField = new JTextField("http://localhost:9200", 20);
    private final JButton testConnectionButton = new JButton("Test Connection");
    private final JLabel testConnectionStatus = new JLabel("");

    public ConfigPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        add(buildSourcesPanel());
        add(Box.createVerticalStrut(10));
        add(buildScopePanel());
        add(Box.createVerticalStrut(10));
        add(buildSinksPanel());
        add(Box.createVerticalStrut(10));
        add(buildSaveButton());
    }

    private JPanel buildSourcesPanel() {
        JPanel sourcesPanel = new JPanel();
        sourcesPanel.setLayout(new BoxLayout(sourcesPanel, BoxLayout.Y_AXIS));
        sourcesPanel.setBorder(BorderFactory.createTitledBorder("Data Sources"));

        sourcesPanel.add(wrapLeftAligned(settingsCheckbox));
        sourcesPanel.add(wrapLeftAligned(sitemapCheckbox));
        sourcesPanel.add(wrapLeftAligned(issuesCheckbox));
        sourcesPanel.add(wrapLeftAligned(trafficCheckbox));

        return sourcesPanel;
    }

    private JPanel buildScopePanel() {
        JPanel scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.Y_AXIS));
        scopePanel.setBorder(BorderFactory.createTitledBorder("Scope"));

        ButtonGroup group = new ButtonGroup();
        group.add(burpSuiteRadio);
        group.add(customRadio);
        group.add(allRadio);

        scopePanel.add(wrapLeftAligned(burpSuiteRadio));

        JPanel customScopeRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        customScopeRow.add(customRadio);
        customScopeRow.add(customScopeField);
        scopePanel.add(customScopeRow);

        scopePanel.add(wrapLeftAligned(allRadio));

        return scopePanel;
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

        testWriteAccessButton.addActionListener(e -> testWriteAccessStatus.setText("Testing write access ."));
        sinksPanel.add(fileRow);

        JPanel openSearchRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        openSearchRow.add(openSearchSinkCheckbox);
        openSearchRow.add(openSearchUrlField);
        openSearchRow.add(testConnectionButton);
        openSearchRow.add(testConnectionStatus);

        // ✅ Only change: use safeTestConnection and clean done()
        testConnectionButton.addActionListener(e -> {
            testConnectionStatus.setText(".");

            new SwingWorker<OpenSearchClientWrapper.OpenSearchStatus, Void>() {
                @Override
                protected OpenSearchClientWrapper.OpenSearchStatus doInBackground() {
                    String url = openSearchUrlField.getText();
                    return OpenSearchClientWrapper.safeTestConnection(url);
                }

                @Override
                protected void done() {
                    try {
                        OpenSearchClientWrapper.OpenSearchStatus status = get();
                        if (status.success()) {
                            testConnectionStatus.setText("✔ " + status.message() +
                                    " (" + status.distribution() + " v" + status.version() + ")");
                        } else {
                            testConnectionStatus.setText("✖ " + status.message());
                        }
                    } catch (Exception ex) {
                        testConnectionStatus.setText("✖ Error: " + ex.getMessage());
                    }
                }
            }.execute();
        });

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
            if (settingsCheckbox.isSelected()) selectedSources.add("settings");
            if (sitemapCheckbox.isSelected()) selectedSources.add("sitemap");
            if (issuesCheckbox.isSelected()) selectedSources.add("findings");
            if (trafficCheckbox.isSelected()) selectedSources.add("traffic");

            String scope = allRadio.isSelected() ? "All"
                    : burpSuiteRadio.isSelected() ? "Burp Suite's"
                    : "Custom: " + customScopeField.getText();

            List<String> selectedSinks = new ArrayList<>();
            if (fileSinkCheckbox.isSelected()) selectedSinks.add("File");
            if (openSearchSinkCheckbox.isSelected()) selectedSinks.add("OpenSearch");

            Logger.logInfo("----------------------------------------");
            Logger.logInfo("Saving config ...");
            Logger.logInfo("  Data source(s): " + String.join(", ", selectedSources));
            Logger.logInfo("  Scope: " + scope);
            Logger.logInfo("  Data Sink(s): " + String.join(", ", selectedSinks));
            Logger.logInfo("  OpenSearch URL: " + openSearchUrlField.getText());

            // ✅ Batch-create OpenSearch indices
            if (openSearchSinkCheckbox.isSelected()) {
                String url = openSearchUrlField.getText();
                for (String shortName : selectedSources) {
                    boolean ok = OpenSearchSink.createIndexFromResource(url, shortName);
                    if (ok) {
                        Logger.logInfo("  ✔ Created or verified index: " + shortName);
                    } else {
                        Logger.logError("  ✖ Failed to create index: " + shortName);
                    }
                }
            }
        }
    }
}
