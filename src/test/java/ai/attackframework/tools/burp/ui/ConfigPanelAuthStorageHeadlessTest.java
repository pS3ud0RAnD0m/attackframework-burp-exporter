package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;

class ConfigPanelAuthStorageHeadlessTest {

    @Test
    void authDefaultsToBasic_andLoadsSessionBasicValues() throws Exception {
        withCleanSession(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("alice", "secret");
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
            JTextField user = get(panel, "openSearchUserField");
            JPasswordField pass = get(panel, "openSearchPasswordField");

            runEdt(() -> assertThat(authType.getSelectedItem()).isEqualTo("Basic"));
            runEdt(() -> {
                assertThat(user.getText()).isEqualTo("alice");
                assertThat(new String(pass.getPassword())).isEqualTo("secret");
            });
        });
    }

    @Test
    void defaultBasicAuth_appliesLoadedSessionCredentialsWithoutAdditionalAction() throws Exception {
        withCleanSession(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("carol", "pw123");
            newPanelOnEdt();
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("carol");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw123");
        });
    }

    @Test
    void defaultBasicAuth_showsBasicCredentialFormOnInitialLoad() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JPanel authForm = get(panel, "openSearchAuthFormPanel");
            Component basicCard = findByName(authForm, "os.authCard.basic");
            Component noneCard = findByName(authForm, "os.authCard.none");
            runEdt(() -> {
                assertThat(isEffectivelyVisible(basicCard)).isTrue();
                assertThat(isEffectivelyVisible(noneCard)).isFalse();
            });
        });
    }

    @Test
    void selectingApiKeyJwtAndCertificate_showsCorrectFormAndLoadsSessionValues() throws Exception {
        withCleanSession(() -> {
            SecureCredentialStore.saveApiKeyCredentials("kid-1", "ksecret-1");
            SecureCredentialStore.saveJwtCredentials("jwt-token-1");
            SecureCredentialStore.saveCertificateCredentials("cert.pem", "cert.key", "passphrase-1");

            ConfigPanel panel = newPanelOnEdt();
            JPanel authForm = get(panel, "openSearchAuthFormPanel");
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");

            JTextField apiKeyId = get(panel, "openSearchApiKeyIdField");
            JPasswordField apiKeySecret = get(panel, "openSearchApiKeySecretField");
            JTextField jwtToken = get(panel, "openSearchJwtTokenField");
            JTextField certPath = get(panel, "openSearchCertPathField");
            JTextField certKeyPath = get(panel, "openSearchCertKeyPathField");
            JPasswordField certPassphrase = get(panel, "openSearchCertPassphraseField");

            Component apiKeyCard = findByName(authForm, "os.authCard.apikey");
            Component jwtCard = findByName(authForm, "os.authCard.jwt");
            Component certCard = findByName(authForm, "os.authCard.certificate");

            runEdt(() -> authType.setSelectedItem("API Key"));
            runEdt(() -> {
                assertThat(isEffectivelyVisible(apiKeyCard)).isTrue();
                assertThat(apiKeyId.getText()).isEqualTo("kid-1");
                assertThat(new String(apiKeySecret.getPassword())).isEqualTo("ksecret-1");
            });

            runEdt(() -> authType.setSelectedItem("JWT"));
            runEdt(() -> {
                assertThat(isEffectivelyVisible(jwtCard)).isTrue();
                assertThat(jwtToken.getText()).isEqualTo("jwt-token-1");
            });

            runEdt(() -> authType.setSelectedItem("Certificate"));
            runEdt(() -> {
                assertThat(isEffectivelyVisible(certCard)).isTrue();
                assertThat(certPath.getText()).isEqualTo("cert.pem");
                assertThat(certKeyPath.getText()).isEqualTo("cert.key");
                assertThat(new String(certPassphrase.getPassword())).isEqualTo("passphrase-1");
            });
        });
   }

    @Test
    void defaultBasicAuth_withEmptySessionStore_keepsVisibleFormAndClearsRuntimeCredentials() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JPanel authForm = get(panel, "openSearchAuthFormPanel");
            JTextField user = get(panel, "openSearchUserField");
            JPasswordField pass = get(panel, "openSearchPasswordField");
            Component basicCard = findByName(authForm, "os.authCard.basic");

            runEdt(() -> {
                assertThat(isEffectivelyVisible(basicCard)).isTrue();
                assertThat(user.getText()).isEmpty();
                assertThat(new String(pass.getPassword())).isEmpty();
            });
            assertThat(RuntimeConfig.openSearchUser()).isEmpty();
            assertThat(RuntimeConfig.openSearchPassword()).isEmpty();
        });
    }

    @Test
    void tlsMode_defaultsToVerify() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> tlsMode = get(panel, "openSearchTlsModeCombo");
            runEdt(() -> assertThat(String.valueOf(tlsMode.getSelectedItem())).isEqualTo("Verify"));
        });
    }

    @Test
    void changingTlsMode_emitsLogPanelEvents() throws Exception {
        withCleanSession(() -> {
            Logger.resetState();
            List<String> events = new CopyOnWriteArrayList<>();
            Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
            Logger.registerListener(listener);
            try {
                ConfigPanel panel = newPanelOnEdt();
                JComboBox<String> tlsMode = get(panel, "openSearchTlsModeCombo");

                runEdt(() -> tlsMode.setSelectedItem("Trust pinned certificate"));
                runEdt(() -> tlsMode.setSelectedItem("Trust all certificates"));

                assertThat(events).anyMatch(message -> message.contains("OpenSearch TLS mode set to Trust pinned certificate."));
                assertThat(events).anyMatch(message -> message.contains("requires an imported pinned certificate before test/start"));
                assertThat(events).anyMatch(message -> message.contains("OpenSearch TLS mode set to Trust all certificates."));
                assertThat(events).anyMatch(message -> message.contains("trusting all certificates insecurely"));
            } finally {
                Logger.unregisterListener(listener);
                Logger.resetState();
            }
        });
    }

    @Test
    void applyPinnedCertificateImport_logsSuccessAndStoresPinnedCertificate() throws Exception {
        withCleanSession(() -> {
            Logger.resetState();
            List<String> events = new CopyOnWriteArrayList<>();
            Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
            Logger.registerListener(listener);
            Path certFile = exportAnyDefaultTrustStoreCertificate();
            try {
                ConfigPanel panel = newPanelOnEdt();
                runEdt(() -> call(panel, "applyPinnedCertificateImport", certFile));

                SecureCredentialStore.PinnedTlsCertificate pinned = SecureCredentialStore.loadPinnedTlsCertificate();
                assertThat(pinned.sourcePath()).isEqualTo(certFile.toAbsolutePath().normalize().toString());
                assertThat(pinned.fingerprintSha256()).isNotBlank();
                assertThat(events).anyMatch(message -> message.contains("Importing OpenSearch pinned TLS certificate from"));
                assertThat(events).anyMatch(message -> message.contains("Imported OpenSearch pinned TLS certificate: fingerprint=")
                        && message.contains(pinned.fingerprintSha256()));
            } finally {
                Files.deleteIfExists(certFile);
                Logger.unregisterListener(listener);
                Logger.resetState();
            }
        });
    }

    @Test
    void testConnectionTooltip_explainsSessionOnlyHandling() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JButton testButton = get(panel, "testConnectionButton");
            JPanel authForm = get(panel, "openSearchAuthFormPanel");
            runEdt(() -> {
                assertThat(testButton.getToolTipText())
                        .isEqualTo("<html>Test connectivity and authentication against OpenSearch.<br>Status output includes connection, authentication, trust, and reported version.<br>Secrets are only stored within in-process memory.</html>");
                assertThat(findByNameOrNull(authForm, "os.authenticate")).isNull();
            });
        });
    }

    @Test
    void saveTooltip_describesSavingCurrentConfiguration() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JButton save = (JButton) findByName(panel, "control.save");
            runEdt(() -> assertThat(save.getToolTipText())
                    .isEqualTo("<html>Save and apply the current configuration.<br>Secrets are only stored within in-process memory.</html>"));
        });
    }

    @Test
    void startTooltip_describesStartingExportToConfiguredDestinations() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JButton start = (JButton) findByName(panel, "control.startStop");
            runEdt(() -> assertThat(start.getToolTipText()).isEqualTo("<html>Start exporting to the configured destination(s).</html>"));
        });
    }

    @Test
    void sourceAndDestinationTooltips_matchSpreadsheetDecisions() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JCheckBox settings = get(panel, "settingsCheckbox");
            JCheckBox issues = get(panel, "issuesCheckbox");
            Component destinationsHeader = findLabelByText(panel, "Destinations");

            runEdt(() -> {
                assertThat(settings.getToolTipText()).isEqualTo("<html>All settings.</html>");
                assertThat(issues.getToolTipText()).isEqualTo("<html>All findings (aka issues).</html>");
                assertThat(((javax.swing.JLabel) destinationsHeader).getToolTipText())
                        .isEqualTo("<html>Configure export destination(s).</html>");
            });
        });
    }

    @Test
    void authControls_have_expected_tooltips() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
            JTextField user = get(panel, "openSearchUserField");
            JPasswordField pass = get(panel, "openSearchPasswordField");
            JTextField apiKeyId = get(panel, "openSearchApiKeyIdField");
            JPasswordField apiKeySecret = get(panel, "openSearchApiKeySecretField");
            JTextField jwtToken = get(panel, "openSearchJwtTokenField");
            JTextField certPath = get(panel, "openSearchCertPathField");
            JTextField certKeyPath = get(panel, "openSearchCertKeyPathField");
            JPasswordField certPassphrase = get(panel, "openSearchCertPassphraseField");

            runEdt(() -> {
                assertThat(authType.getToolTipText()).isEqualTo("<html>Select how requests to OpenSearch authenticate.</html>");
                assertThat(user.getToolTipText()).isEqualTo("<html>OpenSearch Basic auth username.<br>Stored only within in-process memory.</html>");
                assertThat(pass.getToolTipText()).isEqualTo("<html>OpenSearch Basic auth password.<br>Stored only within in-process memory.</html>");
                assertThat(apiKeyId.getToolTipText()).isEqualTo("<html>OpenSearch API key ID.<br>Stored only within in-process memory.</html>");
                assertThat(apiKeySecret.getToolTipText()).isEqualTo("<html>OpenSearch API key secret.<br>Stored only within in-process memory.</html>");
                assertThat(jwtToken.getToolTipText()).isEqualTo("<html>OpenSearch JWT bearer token.<br>Stored only within in-process memory.</html>");
                assertThat(certPath.getToolTipText()).isEqualTo("<html>Path to the client certificate file used for OpenSearch authentication.</html>");
                assertThat(certKeyPath.getToolTipText()).isEqualTo("<html>Path to the client private key file used for OpenSearch authentication.</html>");
                assertThat(certPassphrase.getToolTipText()).isEqualTo("<html>Client key passphrase.<br>Stored only within in-process memory.</html>");

                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Auth type:")).getToolTipText())
                        .isEqualTo("<html>Select how requests to OpenSearch authenticate.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Username:")).getToolTipText())
                        .isEqualTo("<html>OpenSearch Basic auth username.<br>Stored only within in-process memory.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Password:")).getToolTipText())
                        .isEqualTo("<html>OpenSearch Basic auth password.<br>Stored only within in-process memory.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Key ID:")).getToolTipText())
                        .isEqualTo("<html>OpenSearch API key ID.<br>Stored only within in-process memory.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Key Secret:")).getToolTipText())
                        .isEqualTo("<html>OpenSearch API key secret.<br>Stored only within in-process memory.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "JWT Token:")).getToolTipText())
                        .isEqualTo("<html>OpenSearch JWT bearer token.<br>Stored only within in-process memory.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Cert Path:")).getToolTipText())
                        .isEqualTo("<html>Path to the client certificate file used for OpenSearch authentication.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Key Path:")).getToolTipText())
                        .isEqualTo("<html>Path to the client private key file used for OpenSearch authentication.</html>");
                assertThat(((javax.swing.JLabel) findLabelByText(panel, "Passphrase:")).getToolTipText())
                        .isEqualTo("<html>Client key passphrase.<br>Stored only within in-process memory.</html>");
            });
        });
    }

    @Test
    void selectingNone_doesNotEmitAuthenticationClearedStatus() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
            javax.swing.JTextArea status = get(panel, "openSearchStatus");

            runEdt(() -> authType.setSelectedItem("None"));

            assertThat(status.getText()).isEmpty();
        });
    }

    @Test
    void persistSelectedAuthSecrets_cachesBasicCredentialsForCurrentSession() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
            JTextField user = get(panel, "openSearchUserField");
            JPasswordField pass = get(panel, "openSearchPasswordField");

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("bob");
                pass.setText("s3cret");
                ai.attackframework.tools.burp.testutils.Reflect.call(panel, "persistSelectedAuthSecrets");
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("bob");
            assertThat(creds.password()).isEqualTo("s3cret");
        });
    }

    @Test
    void testConnection_appliesAndCachesSelectedBasicAuthForCurrentSession() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
            JTextField user = get(panel, "openSearchUserField");
            JPasswordField pass = get(panel, "openSearchPasswordField");
            JButton testConnection = get(panel, "testConnectionButton");

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("dana");
                pass.setText("pw-conn");
                testConnection.doClick();
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("dana");
            assertThat(creds.password()).isEqualTo("pw-conn");
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("dana");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw-conn");
        });
    }

    @Test
    void enterOnBasicPasswordField_triggersTestConnectionBehavior() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
            JTextField user = get(panel, "openSearchUserField");
            JPasswordField pass = get(panel, "openSearchPasswordField");

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("erin");
                pass.setText("pw-enter");
                pass.postActionEvent();
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("erin");
            assertThat(creds.password()).isEqualTo("pw-enter");
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("erin");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw-enter");
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new ConfigController.Ui() {
                @Override public void onFileStatus(String message) { }
                @Override public void onOpenSearchStatus(String message) { }
                @Override public void onControlStatus(String message) { }
            }));
            p.setSize(1000, 700);
            p.doLayout();
            ref.set(p);
        });
        return ref.get();
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    private static void withCleanSession(CheckedRunnable action) throws Exception {
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(null);
        try {
            action.run();
        } finally {
            SecureCredentialStore.clearAll();
            RuntimeConfig.updateState(null);
        }
    }

    private static Path exportAnyDefaultTrustStoreCertificate() throws Exception {
        Path trustStore = Path.of(System.getProperty("java.home"), "lib", "security", "cacerts");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream input = Files.newInputStream(trustStore)) {
            keyStore.load(input, "changeit".toCharArray());
        }
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                continue;
            }
            Path file = Files.createTempFile("tls-pin-", ".cer");
            Files.write(file, cert.getEncoded());
            return file;
        }
        throw new AssertionError("No certificate found in default trust store");
    }

    private static Component findByName(Container root, String name) {
        Component found = findByNameOrNull(root, name);
        if (found != null) {
            return found;
        }
        throw new AssertionError("Component not found by name: " + name);
    }

    private static Component findByNameOrNull(Container root, String name) {
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName())) {
                return component;
            }
            if (component instanceof Container child) {
                Component nested = findByNameOrNull(child, name);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static Component findLabelByText(Container root, String text) {
        for (Component component : root.getComponents()) {
            if (component instanceof javax.swing.JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                Component nested = findLabelByText(child, text);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static boolean isEffectivelyVisible(Component component) {
        Component current = component;
        while (current != null) {
            if (!current.isVisible()) {
                return false;
            }
            current = current.getParent();
        }
        return true;
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
