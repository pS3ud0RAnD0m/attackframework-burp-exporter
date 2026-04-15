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
            assertThat(findingsLabel.getToolTipText()).isEqualTo("<html>All findings (aka issues) fields.</html>");
            assertThat(findingsExpand.getToolTipText()).isEqualTo("<html>Show or hide fields for all findings (aka issues).</html>");
        } finally {
            MontoyaApiProvider.set(previousApi);
        }
    }

    private static JPanel buildPanelOnEdt() throws Exception {
        AtomicReference<JPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            Map<String, JButton> expandButtons = new LinkedHashMap<>();
            Map<String, JPanel> subPanels = new LinkedHashMap<>();
            JButton findingsExpand = new JButton("+");
            findingsExpand.setName("fields.findings.expand");
            expandButtons.put("findings", findingsExpand);
            subPanels.put("findings", new JPanel());
            JPanel panel = new ConfigFieldsPanel(expandButtons, subPanels, 12).build(new LinkedHashMap<>());
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
