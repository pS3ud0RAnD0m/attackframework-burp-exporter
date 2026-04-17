package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;

class ConfigFieldsPanelTest {

    @Test
    void findingsTooltips_useCommunityUnsupportedCopy_whenCommunityEdition() throws Exception {
        MontoyaApi previousApi = MontoyaApiProvider.get();
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.COMMUNITY_EDITION));
            JPanel panel = buildPanelOnEdt();

            JLabel findingsLabel = findLabelByText(panel, "Findings");
            JButton findingsExpand = findByName(panel, "fields.findings.expand", JButton.class);

            assertThat(findingsLabel).isNotNull();
            assertThat(findingsExpand).isNotNull();
            assertThat(findingsLabel.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
            assertThat(findingsExpand.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
        } finally {
            MontoyaApiProvider.set(previousApi);
        }
    }

    @Test
    void findingsTooltips_useNormalCopy_whenProfessionalEdition() throws Exception {
        MontoyaApi previousApi = MontoyaApiProvider.get();
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.PROFESSIONAL));
            JPanel panel = buildPanelOnEdt();

            JLabel findingsLabel = findLabelByText(panel, "Findings");
            JButton findingsExpand = findByName(panel, "fields.findings.expand", JButton.class);

            assertThat(findingsLabel).isNotNull();
            assertThat(findingsExpand).isNotNull();
            assertThat(findingsLabel.getToolTipText())
                    .isEqualTo("<html><b>Findings fields</b><br>Configure fields exported to the Findings index.<br>The index name can be customized from the Index Base Name field.<br>These fields cover Burp findings (aka issues) documents.</html>");
            assertThat(findingsExpand.getToolTipText()).isEqualTo("<html>Show or hide Findings field options.</html>");
        } finally {
            MontoyaApiProvider.set(previousApi);
        }
    }

    @Test
    void exporterRow_usesExporterIndexCopy() throws Exception {
        MontoyaApi previousApi = MontoyaApiProvider.get();
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.PROFESSIONAL));
            JPanel panel = buildPanelOnEdt();

            JLabel toolLabel = findLabelByText(panel, "Exporter");
            JButton toolExpand = findByName(panel, "fields.tool.expand", JButton.class);
            JLabel indexBaseNameLabel = findLabelByText(panel, "Index Base Name:");

            assertThat(toolLabel).isNotNull();
            assertThat(toolExpand).isNotNull();
            assertThat(indexBaseNameLabel).isNotNull();
            assertThat(toolLabel.getToolTipText()).contains("Exporter index");
            assertThat(toolLabel.getToolTipText()).contains("runtime stats snapshots");
            assertThat(toolExpand.getToolTipText()).isEqualTo("<html>Show or hide Exporter field options.</html>");
        } finally {
            MontoyaApiProvider.set(previousApi);
        }
    }

    @Test
    void professionalEdition_topLevelFieldTooltips_useConsistentStructuredCopy() throws Exception {
        MontoyaApi previousApi = MontoyaApiProvider.get();
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.PROFESSIONAL));
            JPanel panel = buildPanelOnEdt();

            assertTopLevelTooltip(panel, "Settings", "Settings", "Settings index");
            assertTopLevelTooltip(panel, "Sitemap", "Sitemap", "Sitemap index");
            assertTopLevelTooltip(panel, "Findings", "Findings", "Findings index");
            assertTopLevelTooltip(panel, "Traffic", "Traffic", "Traffic index");
            assertTopLevelTooltip(panel, "Exporter", "Exporter", "Exporter index");
        } finally {
            MontoyaApiProvider.set(previousApi);
        }
    }

    private static JPanel buildPanelOnEdt() throws Exception {
        AtomicReference<JPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            Map<String, JButton> expandButtons = new LinkedHashMap<>();
            Map<String, JPanel> subPanels = new LinkedHashMap<>();
            addIndexRow(expandButtons, subPanels, "settings");
            addIndexRow(expandButtons, subPanels, "sitemap");
            addIndexRow(expandButtons, subPanels, "findings");
            addIndexRow(expandButtons, subPanels, "traffic");
            addIndexRow(expandButtons, subPanels, "tool");
            JPanel namingPanel = new JPanel();
            namingPanel.add(new JLabel("Index Base Name:"));
            JPanel panel = new ConfigFieldsPanel(expandButtons, subPanels, namingPanel, 12).build(new LinkedHashMap<>());
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static MontoyaApi mockEditionApi(BurpSuiteEdition edition) {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(edition);
        return api;
    }

    private static void assertTopLevelTooltip(JPanel panel, String labelText, String displayName, String indexNamePhrase) {
        JLabel label = findLabelByText(panel, labelText);
        JButton expand = findByName(panel, "fields." + ("Exporter".equals(displayName) ? "tool" : displayName.toLowerCase()) + ".expand", JButton.class);
        assertThat(label).isNotNull();
        assertThat(expand).isNotNull();
        assertThat(label.getToolTipText()).contains("<b>" + displayName + " fields</b>");
        assertThat(label.getToolTipText()).contains("Configure fields exported to the " + indexNamePhrase + ".");
        assertThat(label.getToolTipText()).contains("The index name can be customized from the Index Base Name field.");
        assertThat(expand.getToolTipText()).isEqualTo("<html>Show or hide " + displayName + " field options.</html>");
    }

    private static void addIndexRow(Map<String, JButton> expandButtons, Map<String, JPanel> subPanels, String indexKey) {
        JButton expand = new JButton("+");
        expand.setName("fields." + indexKey + ".expand");
        expandButtons.put(indexKey, expand);
        subPanels.put(indexKey, new JPanel());
    }

    private static JLabel findLabelByText(Container root, String text) {
        if (root instanceof JLabel label && text.equals(label.getText())) {
            return label;
        }
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                JLabel nested = findLabelByText(child, text);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            if (type.isInstance(component)) {
                T typedComponent = type.cast(component);
                if (name.equals(typedComponent.getName())) {
                    return typedComponent;
                }
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }
}
