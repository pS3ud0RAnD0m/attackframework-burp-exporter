package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink;
import ai.attackframework.vectors.sources.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.vectors.sources.burp.utils.Logger;
import ai.attackframework.vectors.sources.burp.utils.files.FilesUtil;
import ai.attackframework.vectors.sources.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.attackframework.vectors.sources.burp.utils.IndexNaming;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ConfigPanel extends JPanel {

    private final JCheckBox settingsCheckbox = new JCheckBox("Settings", true);
    private final JCheckBox sitemapCheckbox  = new JCheckBox("Sitemap",  true);
    private final JCheckBox issuesCheckbox   = new JCheckBox("Issues",   true);
    private final JCheckBox trafficCheckbox  = new JCheckBox("Traffic",  true);

    private final JRadioButton allRadio       = new JRadioButton("All");
    private final JRadioButton burpSuiteRadio = new JRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio    = new JRadioButton("Custom (RegEx)");
    private final JTextField   customScopeField = new JTextField("^.*acme\\.com$");

    private final JCheckBox fileSinkCheckbox = new JCheckBox("Files", true);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JButton    createFilesButton = new JButton("Create Files");
    private final JTextArea  fileStatus = new JTextArea();
    private final JPanel     fileStatusWrapper = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    private final JCheckBox openSearchSinkCheckbox = new JCheckBox("OpenSearch", false);
    @SuppressWarnings("HttpUrlsUsage")
    private final JTextField openSearchUrlField    = new AutoSizingTextField("http://opensearch.url:9200");
    private final JButton    testConnectionButton  = new JButton("Test Connection");
    private final JButton    createIndexesButton   = new JButton("Create Indexes");
    private final JTextArea  openSearchStatus      = new JTextArea();
    private final JPanel     statusWrapper         = new JPanel(new MigLayout("insets 5, novisualpadding", "[pref!]"));

    public ConfigPanel() {
        setLayout(new MigLayout("fillx, insets 12", "[fill]"));
        setPreferredSize(new Dimension(1200, 600));

        add(buildSourcesPanel(), "gaptop 5, gapbottom 5, wrap");
        add(thickSeparator(), "growx, wrap");

        add(buildScopePanel(), "gaptop 10, gapbottom 5, wrap");
        add(thickSeparator(), "growx, wrap");

        add(buildSinksPanel(), "gaptop 10, gapbottom 5, wrap");
        add(thickSeparator(), "growx, wrap");

        add(buildSavePanel(), "growx, wrap");
        add(Box.createVerticalGlue(), "growy, wrap");
    }

    private JPanel buildSourcesPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sources");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        panel.add(settingsCheckbox, "gapleft 30");
        panel.add(sitemapCheckbox,  "gapleft 30");
        panel.add(issuesCheckbox,   "gapleft 30");
        panel.add(trafficCheckbox,  "gapleft 30");

        return panel;
    }

    private JPanel buildScopePanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Scope");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(burpSuiteRadio);
        scopeGroup.add(customRadio);
        scopeGroup.add(allRadio);

        panel.add(burpSuiteRadio, "gapleft 30");

        JPanel customRow = new JPanel(new MigLayout("insets 0", "[]20[]", ""));
        customRow.add(customRadio);
        customRow.add(customScopeField);
        panel.add(customRow, "gapleft 30");

        panel.add(allRadio, "gapleft 30");

        return panel;
    }

    private JPanel buildSinksPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[grow]"));
        panel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel header = new JLabel("Data Sinks");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        // ---------- File row ----------
        JPanel fileRow = new JPanel(new MigLayout(
                "insets 0",
                "[150!, left]20[pref]20[left]20[left, grow]"
        ));
        fileRow.setAlignmentX(LEFT_ALIGNMENT);

        fileRow.add(fileSinkCheckbox, "gapleft 30, alignx left, top");
        fileRow.add(filePathField,    "alignx left, top");
        fileRow.add(createFilesButton, "alignx left, top");

        configureTextArea(fileStatus);
        fileStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        fileStatusWrapper.removeAll();
        fileStatusWrapper.add(fileStatus, "w pref!");
        fileStatusWrapper.setVisible(false);
        fileRow.add(fileStatusWrapper, "hidemode 3, alignx left, w pref!, wrap");

        panel.add(fileRow, "growx, wrap");

        // ---------- OpenSearch row ----------
        JPanel osRow = new JPanel(new MigLayout(
                "insets 0",
                "[150!, left]20[pref]20[left]20[left, grow]"
        ));
        osRow.setAlignmentX(LEFT_ALIGNMENT);

        osRow.add(openSearchSinkCheckbox, "gapleft 30, top");
        osRow.add(openSearchUrlField,     "alignx left, top");
        osRow.add(testConnectionButton,   "split 2, alignx left, top");
        osRow.add(createIndexesButton,    "alignx left, top");

        configureTextArea(openSearchStatus);
        statusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        statusWrapper.removeAll();
        statusWrapper.add(openSearchStatus, "w pref!");
        statusWrapper.setVisible(false);
        osRow.add(statusWrapper, "hidemode 3, alignx left, w pref!, wrap");

        panel.add(osRow, "growx, wrap");

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

    private JComponent thickSeparator() {
        return new JSeparator() {
            @Override
            public Dimension getPreferredSize() {
                return new Dimension(super.getPreferredSize().width, 4);
            }

            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(getForeground());
                g.fillRect(0, 1, getWidth(), 2);
            }
        };
    }

    private void configureTextArea(JTextArea area) {
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setRows(1);
        area.setColumns(1);
    }

    private void updateStatus(String message) {
        openSearchStatus.setText(message);

        String[] lines = message.split("\r\n|\r|\n", -1);
        int rows = Math.max(lines.length, 1);
        int cols = Math.min(200, Math.max(20, maxLineLength(lines)));

        openSearchStatus.setRows(rows);
        openSearchStatus.setColumns(cols);

        statusWrapper.setVisible(true);
        statusWrapper.revalidate();
        statusWrapper.repaint();
    }

    private void updateFileStatus(String message) {
        fileStatus.setText(message);

        String[] lines = message.split("\r\n|\r|\n", -1);
        int rows = Math.max(lines.length, 1);
        int cols = Math.min(200, Math.max(20, maxLineLength(lines)));

        fileStatus.setRows(rows);
        fileStatus.setColumns(cols);

        fileStatusWrapper.setVisible(true);
        fileStatusWrapper.revalidate();
        fileStatusWrapper.repaint();
    }

    private static int maxLineLength(String[] lines) {
        int max = 1;
        for (String s : lines) {
            if (s != null && s.length() > max) max = s.length();
        }
        return max;
    }

    private void wireButtonActions() {
        createFilesButton.addActionListener(e -> {
            String root = filePathField.getText().trim();
            updateFileStatus("Creating files in " + root + " ...");

            List<String> baseNames = IndexNaming.computeIndexBaseNames(getSelectedSources());
            List<String> jsonNames = IndexNaming.toJsonFileNames(baseNames);

            List<FilesUtil.CreateResult> results = FilesUtil.ensureJsonFiles(Path.of(root), jsonNames);

            List<String> created = new ArrayList<>();
            List<String> exists  = new ArrayList<>();
            List<String> failed  = new ArrayList<>();

            for (FilesUtil.CreateResult r : results) {
                switch (r.status()) {
                    case CREATED -> created.add(r.path().toString());
                    case EXISTS  -> exists.add(r.path().toString());
                    case FAILED  -> failed.add(r.path().toString() + " — " + r.error());
                }
            }

            StringBuilder sb = new StringBuilder();
            if (!created.isEmpty()) {
                sb.append(created.size() == 1 ? "File created:\n  " : "Files created:\n  ")
                        .append(String.join("\n  ", created)).append("\n");
            }
            if (!exists.isEmpty()) {
                sb.append(exists.size() == 1 ? "File already existed:\n  " : "Files already existed:\n  ")
                        .append(String.join("\n  ", exists)).append("\n");
            }
            if (!failed.isEmpty()) {
                sb.append(failed.size() == 1 ? "File creation failed:\n  " : "File creations failed:\n  ")
                        .append(String.join("\n  ", failed)).append("\n");
            }

            updateFileStatus(sb.toString().trim());
        });

        testConnectionButton.addActionListener(e -> {
            updateStatus("Testing ...");

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
                            updateStatus(status.message() +
                                    " (" + status.distribution() + " v" + status.version() + ")");
                            Logger.logInfo("OpenSearch connection successful: " + status.message() +
                                    " (" + status.distribution() + " v" + status.version() + ") at " + openSearchUrlField.getText());
                        } else {
                            updateStatus("✖ " + status.message());
                            Logger.logError("OpenSearch connection failed: " + status.message());
                        }
                    } catch (Exception ex) {
                        updateStatus("✖ Error: " + ex.getMessage());
                        Logger.logError("OpenSearch connection error: " + ex.getMessage());
                    }
                }
            }.execute();
        });

        createIndexesButton.addActionListener(e -> {
            updateStatus("Creating indexes . . .");

            new SwingWorker<List<IndexResult>, Void>() {
                @Override
                protected List<IndexResult> doInBackground() {
                    return OpenSearchSink.createSelectedIndexes(openSearchUrlField.getText(), getSelectedSources());
                }

                @Override
                protected void done() {
                    try {
                        List<IndexResult> results = get();

                        List<String> created = new ArrayList<>();
                        List<String> exists  = new ArrayList<>();
                        List<String> failed  = new ArrayList<>();

                        for (IndexResult r : results) {
                            switch (r.status()) {
                                case CREATED -> created.add(r.fullName());
                                case EXISTS  -> exists.add(r.fullName());
                                case FAILED  -> failed.add(r.fullName());
                            }
                        }

                        boolean allExist = !results.isEmpty() &&
                                results.stream().allMatch(r -> r.status() == IndexResult.Status.EXISTS);

                        StringBuilder sb = new StringBuilder();
                        if (!created.isEmpty()) {
                            sb.append(created.size() == 1 ? "Index created:\n  " : "Indexes created:\n  ")
                                    .append(String.join("\n  ", created)).append("\n");
                        }
                        if (!exists.isEmpty()) {
                            sb.append(exists.size() == 1 ? "Index already existed:\n  " : "Indexes already existed:\n  ")
                                    .append(String.join("\n  ", exists)).append("\n");
                        }
                        if (!failed.isEmpty()) {
                            sb.append(failed.size() == 1 ? "Index failed:\n  " : "Indexes failed:\n  ")
                                    .append(String.join("\n  ", failed)).append("\n");
                        }

                        if (allExist) {
                            Logger.logInfo("All indexes already existed — no creation performed.");
                        }

                        updateStatus(sb.toString().trim());

                    } catch (Exception ex) {
                        updateStatus("Index creation error: " + ex.getMessage());
                        Logger.logError("Index creation error: " + ex.getMessage());
                    }
                }
            }.execute();
        });

        DocumentListener relayout = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void removeUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
            public void changedUpdate(DocumentEvent e) { filePathField.revalidate(); openSearchUrlField.revalidate(); }
        };
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
    }

    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add("settings");
        if (sitemapCheckbox.isSelected())  selected.add("sitemap");
        if (issuesCheckbox.isSelected())   selected.add("findings");
        if (trafficCheckbox.isSelected())  selected.add("traffic");
        return selected;
    }

    private static class AutoSizingTextField extends JTextField {
        public AutoSizingTextField(String text) {
            super(text);
        }

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int textWidth = fm.stringWidth(getText()) + 20;
            int height = super.getPreferredSize().height;
            return new Dimension(textWidth, height);
        }
    }

    private class SaveButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            List<String> selectedSources = getSelectedSources();
            String scope = allRadio.isSelected() ? "All"
                    : burpSuiteRadio.isSelected() ? "Burp Suite's"
                    : "Custom: " + customScopeField.getText();

            List<String> selectedSinks = new ArrayList<>();
            if (fileSinkCheckbox.isSelected())       selectedSinks.add("Files");
            if (openSearchSinkCheckbox.isSelected()) selectedSinks.add("OpenSearch");

            String sinkLine = "  Data Sink(s): " + String.join(", ", selectedSinks);
            if (openSearchSinkCheckbox.isSelected()) {
                sinkLine += " (" + openSearchUrlField.getText() + ")";
            }

            Logger.logInfo("Saving config ...");
            Logger.logInfo("  Data source(s): " + String.join(", ", selectedSources));
            Logger.logInfo("  Scope: " + scope);
            Logger.logInfo(sinkLine);
        }
    }
}
