package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink;
import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.vectors.sources.burp.utils.Logger;
import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchClientWrapper;
import net.miginfocom.swing.MigLayout;

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
    private final JTextField customScopeField = new JTextField("^.*acme\\.com$", 0);

    private final JCheckBox fileSinkCheckbox = new JCheckBox("File", true);
    private final JTextField filePathField = new JTextField("/path/to/acme.com-burp.json", 0);
    private final JButton testWriteAccessButton = new JButton("Test Write Access");
    private final JLabel testWriteAccessStatus = new JLabel("");

    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    @SuppressWarnings("HttpUrlsUsage")
    private final JTextField openSearchUrlField = new JTextField("http://opensearch.acme.com:9200", 0);
    private final JButton testConnectionButton = new JButton("Test Connection");
    private final JButton createIndexesButton = new JButton("Create Indexes");

    private final JTextArea testConnectionStatus = new JTextArea();
    private final JTextArea createIndexesStatus = new JTextArea();

    public ConfigPanel() {
        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        add(buildSourcesPanel(), "wrap");
        add(buildScopePanel(), "wrap");
        add(buildSinksPanel(), "growx, wrap");
        add(buildSavePanel(), "growx, wrap");
        add(Box.createVerticalGlue(), "growy, wrap");
    }

    private JPanel buildSourcesPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 10, wrap 1", "[left]"));
        panel.setBorder(BorderFactory.createTitledBorder("Data Sources"));
        panel.add(settingsCheckbox);
        panel.add(sitemapCheckbox);
        panel.add(issuesCheckbox);
        panel.add(trafficCheckbox);
        return panel;
    }

    private JPanel buildScopePanel() {
        JPanel panel = new JPanel(new MigLayout("insets 10, wrap 1", "[left]"));
        panel.setBorder(BorderFactory.createTitledBorder("Scope"));

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(burpSuiteRadio);
        scopeGroup.add(customRadio);
        scopeGroup.add(allRadio);

        panel.add(burpSuiteRadio);
        JPanel customRow = new JPanel(new MigLayout("insets 0", "[][]", ""));
        customRow.add(customRadio);
        customRow.add(customScopeField, "growx, pushx");
        panel.add(customRow);
        panel.add(allRadio);

        return panel;
    }

    private JPanel buildSinksPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 10, wrap 2", "[left]10[grow,fill]"));
        panel.setBorder(BorderFactory.createTitledBorder("Data Sinks"));

        panel.add(fileSinkCheckbox, "");
        panel.add(filePathField, "wrap");
        panel.add(testWriteAccessButton, "");
        panel.add(testWriteAccessStatus, "wrap");

        panel.add(openSearchSinkCheckbox, "");
        panel.add(openSearchUrlField, "wrap");
        panel.add(testConnectionButton, "");
        panel.add(createIndexesButton, "wrap");

        configureTextArea(testConnectionStatus);
        configureTextArea(createIndexesStatus);
        panel.add(testConnectionStatus, "span 2, growx, wrap");
        panel.add(createIndexesStatus, "span 2, growx, wrap");

        wireButtonActions();

        return panel;
    }

    private JPanel buildSavePanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0", "[]"));
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(new SaveButtonListener());
        panel.add(saveButton);
        return panel;
    }

    private void configureTextArea(JTextArea area) {
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setMargin(new Insets(4, 10, 4, 4));
        area.setRows(2);
    }

    private void wireButtonActions() {
        testConnectionButton.addActionListener(e -> {
            testConnectionStatus.setText("Testing  . . .");
            createIndexesStatus.setText("");

            new SwingWorker<OpenSearchClientWrapper.OpenSearchStatus, Void>() {
                @Override
                protected OpenSearchClientWrapper.OpenSearchStatus doInBackground() {
                    return OpenSearchClientWrapper.safeTestConnection(openSearchUrlField.getText());
                }

                @Override
                protected void done() {
                    try {
                        OpenSearchClientWrapper.OpenSearchStatus status = get();
                        if (status.success()) {
                            testConnectionStatus.setText("✔ " + status.message() +
                                    " (" + status.distribution() + " v" + status.version() + ")");
                            Logger.logInfo("OpenSearch connection successful: " + status.message() +
                                    " (" + status.distribution() + " v" + status.version() + ") at " + openSearchUrlField.getText());
                        } else {
                            testConnectionStatus.setText("✖ " + status.message());
                            Logger.logError("OpenSearch connection failed: " + status.message());
                        }
                    } catch (Exception ex) {
                        testConnectionStatus.setText("✖ Error: " + ex.getMessage());
                        Logger.logError("OpenSearch connection error: " + ex.getMessage());
                    }
                }
            }.execute();
        });

        createIndexesButton.addActionListener(e -> {
            createIndexesStatus.setText("Creating indexes . . .");
            testConnectionStatus.setText("");

            new SwingWorker<List<IndexResult>, Void>() {
                @Override
                protected List<IndexResult> doInBackground() {
                    return OpenSearchSink.createSelectedIndexes(openSearchUrlField.getText(), getSelectedSources());
                }

                @Override
                protected void done() {
                    try {
                        List<IndexResult> results = get();
                        if (results.isEmpty()) {
                            createIndexesStatus.setText("✔ No indexes needed");
                            Logger.logInfo("No index creation needed; all already exist.");
                            return;
                        }

                        List<String> created = new ArrayList<>();
                        List<String> exists = new ArrayList<>();
                        List<String> failed = new ArrayList<>();

                        for (IndexResult r : results) {
                            switch (r.status()) {
                                case CREATED -> created.add(r.fullName());
                                case EXISTS -> exists.add(r.fullName());
                                case FAILED -> failed.add(r.fullName());
                            }
                        }

                        StringBuilder sb = new StringBuilder();
                        if (!created.isEmpty()) sb.append("Indexes created: ").append(String.join(", ", created)).append("\n");
                        if (!exists.isEmpty()) sb.append("Indexes already exist: ").append(String.join(", ", exists)).append("\n");
                        if (!failed.isEmpty()) sb.append("Failed: ").append(String.join(", ", failed)).append("\n");

                        createIndexesStatus.setText(sb.toString().trim());

                    } catch (Exception ex) {
                        createIndexesStatus.setText("Index creation error: " + ex.getMessage());
                        Logger.logError("Index creation error: " + ex.getMessage());
                    }
                }
            }.execute();
        });
    }

    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add("settings");
        if (sitemapCheckbox.isSelected()) selected.add("sitemap");
        if (issuesCheckbox.isSelected()) selected.add("findings");
        if (trafficCheckbox.isSelected()) selected.add("traffic");
        return selected;
    }

    private class SaveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            List<String> selectedSources = getSelectedSources();
            String scope = allRadio.isSelected() ? "All"
                    : burpSuiteRadio.isSelected() ? "Burp Suite's"
                    : "Custom: " + customScopeField.getText();

            List<String> selectedSinks = new ArrayList<>();
            if (fileSinkCheckbox.isSelected()) selectedSinks.add("File");
            if (openSearchSinkCheckbox.isSelected()) selectedSinks.add("OpenSearch");

            Logger.logInfo("Saving config ...");
            Logger.logInfo("  Data source(s): " + String.join(", ", selectedSources));
            Logger.logInfo("  Scope: " + scope);
            Logger.logInfo("  Data Sink(s): " + String.join(", ", selectedSinks));
            Logger.logInfo("  OpenSearch URL: " + openSearchUrlField.getText());
        }
    }
}
