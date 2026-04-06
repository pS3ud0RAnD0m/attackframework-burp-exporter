package ai.attackframework.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.ui.primitives.TriStateCheckBox;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConfigPanelCommunityEditionHeadlessTest {

    private static void cleanupState() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.updateState(null);
    }

    @Test
    void communityEdition_disables_findings_and_limited_traffic_options_and_shows_notices() throws Exception {
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.COMMUNITY_EDITION);

            TriStateCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox");
            JButton issuesExpandButton = Reflect.get(panel, "issuesExpandButton");
            JCheckBox issuesCriticalCheckbox = Reflect.get(panel, "issuesCriticalCheckbox");
            JCheckBox issuesHighCheckbox = Reflect.get(panel, "issuesHighCheckbox");
            JCheckBox issuesMediumCheckbox = Reflect.get(panel, "issuesMediumCheckbox");
            JCheckBox issuesLowCheckbox = Reflect.get(panel, "issuesLowCheckbox");
            JCheckBox issuesInformationalCheckbox = Reflect.get(panel, "issuesInformationalCheckbox");
            JCheckBox trafficBurpAiCheckbox = Reflect.get(panel, "trafficBurpAiCheckbox");
            JCheckBox trafficExtensionsCheckbox = Reflect.get(panel, "trafficExtensionsCheckbox");
            JCheckBox trafficIntruderCheckbox = Reflect.get(panel, "trafficIntruderCheckbox");
            JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox");
            JCheckBox trafficProxyHistoryCheckbox = Reflect.get(panel, "trafficProxyHistoryCheckbox");
            JCheckBox trafficRepeaterCheckbox = Reflect.get(panel, "trafficRepeaterCheckbox");
            JCheckBox trafficScannerCheckbox = Reflect.get(panel, "trafficScannerCheckbox");
            JCheckBox trafficSequencerCheckbox = Reflect.get(panel, "trafficSequencerCheckbox");
            TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox");
            JPanel issuesNotice = findByName(panel, "src.issues.communityNotice", JPanel.class);
            JLabel issuesNoticeIcon = findByName(panel, "src.issues.communityNotice.icon", JLabel.class);
            JPanel trafficBurpAiNotice = findByName(panel, "src.traffic.burp_ai.communityNotice", JPanel.class);
            JLabel trafficBurpAiNoticeIcon = findByName(panel, "src.traffic.burp_ai.communityNotice.icon", JLabel.class);
            JPanel trafficScannerNotice = findByName(panel, "src.traffic.scanner.communityNotice", JPanel.class);
            JLabel trafficScannerNoticeIcon = findByName(panel, "src.traffic.scanner.communityNotice.icon", JLabel.class);
            Map<String, JPanel> headerRows = Reflect.get(panel, "fieldsSectionHeaderRows");
            Map<String, JPanel> subPanels = Reflect.get(panel, "fieldsSubPanels");
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex = Reflect.get(panel, "fieldCheckboxesByIndex");

            runEdt(() -> {
                assertThat(issuesCheckbox.isEnabled()).isFalse();
                assertThat(issuesCheckbox.isSelected()).isFalse();
                assertThat(issuesExpandButton.isEnabled()).isFalse();
                assertThat(issuesCheckbox.getToolTipText()).isEqualTo("<html>All findings (aka issues).</html>");

                for (JCheckBox checkbox : List.of(
                        issuesCriticalCheckbox,
                        issuesHighCheckbox,
                        issuesMediumCheckbox,
                        issuesLowCheckbox,
                        issuesInformationalCheckbox)) {
                    assertThat(checkbox.isEnabled()).isFalse();
                    assertThat(checkbox.isSelected()).isFalse();
                }

                assertThat(trafficBurpAiCheckbox.isEnabled()).isFalse();
                assertThat(trafficBurpAiCheckbox.isSelected()).isFalse();
                assertThat(trafficExtensionsCheckbox.isSelected()).isTrue();
                assertThat(trafficIntruderCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyHistoryCheckbox.isSelected()).isTrue();
                assertThat(trafficRepeaterCheckbox.isSelected()).isTrue();
                assertThat(trafficScannerCheckbox.isEnabled()).isFalse();
                assertThat(trafficScannerCheckbox.isSelected()).isFalse();
                assertThat(trafficSequencerCheckbox.isSelected()).isTrue();
                assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);

                assertThat(issuesNotice.isVisible()).isTrue();
                assertThat(issuesNoticeIcon.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
                assertThat(trafficBurpAiNotice.isVisible()).isTrue();
                assertThat(trafficBurpAiNoticeIcon.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
                assertThat(trafficScannerNotice.isVisible()).isTrue();
                assertThat(trafficScannerNoticeIcon.getToolTipText()).isEqualTo("<html>Unsupported in Community Edition.</html>");
            });

            assertThat(sectionEnabled("findings", headerRows, subPanels, fieldCheckboxesByIndex)).isFalse();
        } finally {
            cleanupState();
        }
    }

    @Test
    void professionalEdition_keeps_controls_enabled_and_hides_community_notices() throws Exception {
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.PROFESSIONAL);

            TriStateCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox");
            JButton issuesExpandButton = Reflect.get(panel, "issuesExpandButton");
            TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox");
            JCheckBox trafficBurpAiCheckbox = Reflect.get(panel, "trafficBurpAiCheckbox");
            JCheckBox trafficExtensionsCheckbox = Reflect.get(panel, "trafficExtensionsCheckbox");
            JCheckBox trafficIntruderCheckbox = Reflect.get(panel, "trafficIntruderCheckbox");
            JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox");
            JCheckBox trafficProxyHistoryCheckbox = Reflect.get(panel, "trafficProxyHistoryCheckbox");
            JCheckBox trafficRepeaterCheckbox = Reflect.get(panel, "trafficRepeaterCheckbox");
            JCheckBox trafficScannerCheckbox = Reflect.get(panel, "trafficScannerCheckbox");
            JCheckBox trafficSequencerCheckbox = Reflect.get(panel, "trafficSequencerCheckbox");
            JPanel issuesNotice = findByName(panel, "src.issues.communityNotice", JPanel.class);
            JPanel trafficBurpAiNotice = findByName(panel, "src.traffic.burp_ai.communityNotice", JPanel.class);
            JPanel trafficScannerNotice = findByName(panel, "src.traffic.scanner.communityNotice", JPanel.class);

            runEdt(() -> {
                assertThat(issuesCheckbox.isEnabled()).isTrue();
                assertThat(issuesExpandButton.isEnabled()).isTrue();
                assertThat(issuesCheckbox.getToolTipText()).isEqualTo("<html>All findings (aka issues).</html>");
                assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
                assertThat(trafficBurpAiCheckbox.isEnabled()).isTrue();
                assertThat(trafficBurpAiCheckbox.isSelected()).isTrue();
                assertThat(trafficExtensionsCheckbox.isSelected()).isTrue();
                assertThat(trafficIntruderCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
                assertThat(trafficProxyHistoryCheckbox.isSelected()).isTrue();
                assertThat(trafficRepeaterCheckbox.isSelected()).isTrue();
                assertThat(trafficScannerCheckbox.isEnabled()).isTrue();
                assertThat(trafficScannerCheckbox.isSelected()).isTrue();
                assertThat(trafficSequencerCheckbox.isSelected()).isTrue();
                assertThat(issuesNotice.isVisible()).isFalse();
                assertThat(trafficBurpAiNotice.isVisible()).isFalse();
                assertThat(trafficScannerNotice.isVisible()).isFalse();
            });
        } finally {
            cleanupState();
        }
    }

    @Test
    void importing_config_in_community_reapplies_source_restrictions() throws Exception {
        try {
            ConfigPanel panel = createPanel(BurpSuiteEdition.COMMUNITY_EDITION);
            TriStateCheckBox issuesCheckbox = Reflect.get(panel, "issuesCheckbox");
            TriStateCheckBox trafficCheckbox = Reflect.get(panel, "trafficCheckbox");
            JCheckBox issuesCriticalCheckbox = Reflect.get(panel, "issuesCriticalCheckbox");
            JCheckBox trafficBurpAiCheckbox = Reflect.get(panel, "trafficBurpAiCheckbox");
            JCheckBox trafficScannerCheckbox = Reflect.get(panel, "trafficScannerCheckbox");
            JCheckBox trafficProxyCheckbox = Reflect.get(panel, "trafficProxyCheckbox");

            ConfigState.State imported = new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("burp_ai", "scanner", "proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null,
                    null
            );

            runEdt(() -> panel.onImportResult(imported));

            runEdt(() -> {
                assertThat(issuesCheckbox.isEnabled()).isFalse();
                assertThat(issuesCheckbox.isSelected()).isFalse();
                assertThat(issuesCriticalCheckbox.isEnabled()).isFalse();
                assertThat(issuesCriticalCheckbox.isSelected()).isFalse();

                assertThat(trafficCheckbox.isSelected()).isTrue();
                assertThat(trafficBurpAiCheckbox.isEnabled()).isFalse();
                assertThat(trafficBurpAiCheckbox.isSelected()).isFalse();
                assertThat(trafficScannerCheckbox.isEnabled()).isFalse();
                assertThat(trafficScannerCheckbox.isSelected()).isFalse();
                assertThat(trafficProxyCheckbox.isEnabled()).isTrue();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
            });

            runEdt(() -> {
                trafficCheckbox.doClick();
                trafficCheckbox.doClick();
            });

            runEdt(() -> {
                assertThat(trafficCheckbox.getState()).isEqualTo(TriStateCheckBox.State.SELECTED);
                assertThat(trafficBurpAiCheckbox.isSelected()).isFalse();
                assertThat(trafficScannerCheckbox.isSelected()).isFalse();
                assertThat(trafficProxyCheckbox.isSelected()).isTrue();
            });
        } finally {
            cleanupState();
        }
    }

    private static ConfigPanel createPanel(BurpSuiteEdition edition) throws Exception {
        cleanupState();
        MontoyaApiProvider.set(mockMontoyaApi(edition));
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
                panel.setSize(1000, 700);
                panel.doLayout();
                ref.set(panel);
            });
            return ref.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Failed to create ConfigPanel Community edition fixture", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw new RuntimeException(
                    "Failed to create ConfigPanel Community edition fixture", cause != null ? cause : e);
        }
    }

    private static MontoyaApi mockMontoyaApi(BurpSuiteEdition edition) {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(edition);
        return api;
    }

    private static void runEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        String componentName = root.getName();
        if (name.equals(componentName) && type.isInstance(root)) {
            return type.cast(root);
        }
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName()) && type.isInstance(component)) {
                return type.cast(component);
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

    private static boolean sectionEnabled(
            String indexName,
            Map<String, JPanel> headerRows,
            Map<String, JPanel> subPanels,
            Map<String, Map<String, JCheckBox>> fieldCheckboxesByIndex) {
        JPanel header = headerRows != null ? headerRows.get(indexName) : null;
        if (header != null && !header.isEnabled()) {
            return false;
        }
        JPanel sub = subPanels != null ? subPanels.get(indexName) : null;
        if (sub != null && !sub.isEnabled()) {
            return false;
        }
        Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex != null ? fieldCheckboxesByIndex.get(indexName) : null;
        if (checkboxes != null) {
            for (JCheckBox checkbox : checkboxes.values()) {
                if (!checkbox.isEnabled()) {
                    return false;
                }
            }
        }
        return true;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onOpenSearchStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
