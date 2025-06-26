package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.utils.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class AttackVectorsTab extends JPanel {

    private final JCheckBox selectAllSources = new JCheckBox("Select All Sources");
    private final JCheckBox sitemap = new JCheckBox("Sitemap");
    private final JCheckBox issues = new JCheckBox("Issues");
    private final JCheckBox traffic = new JCheckBox("All Traffic");

    private final JCheckBox selectAllSinks = new JCheckBox("Select All Sinks");
    private final JCheckBox openSearch = new JCheckBox("OpenSearch");

    public AttackVectorsTab() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        add(buildSection("Data Sources", selectAllSources, List.of(sitemap, issues, traffic)));
        add(Box.createVerticalStrut(15));
        add(buildSection("Sink Targets", selectAllSinks, List.of(openSearch)));
        add(Box.createVerticalStrut(15));

        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        saveButton.addActionListener(this::onSaveClicked);
        add(saveButton);

        setupSelectAll(selectAllSources, List.of(sitemap, issues, traffic));
        setupSelectAll(selectAllSinks, List.of(openSearch));
    }

    private JPanel buildSection(String title, JCheckBox selectAll, List<JCheckBox> checkboxes) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setBorder(BorderFactory.createTitledBorder(title));

        panel.add(selectAll);
        for (JCheckBox box : checkboxes) {
            panel.add(box);
        }
        return panel;
    }

    private void setupSelectAll(JCheckBox master, List<JCheckBox> targets) {
        master.addActionListener(e -> {
            boolean selected = master.isSelected();
            for (JCheckBox cb : targets) {
                cb.setSelected(selected);
            }
        });
    }

    private void onSaveClicked(ActionEvent e) {
        List<String> selectedSources = new ArrayList<>();
        if (sitemap.isSelected()) selectedSources.add("Sitemap");
        if (issues.isSelected()) selectedSources.add("Issues");
        if (traffic.isSelected()) selectedSources.add("All Traffic");

        List<String> selectedSinks = new ArrayList<>();
        if (openSearch.isSelected()) selectedSinks.add("OpenSearch");

        Logger.logInfo("Sources selected: " + String.join(", ", selectedSources));
        Logger.logInfo("Sinks selected: " + String.join(", ", selectedSinks));
    }
}
