package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.SecureStoreMontoyaMock;
import ai.attackframework.tools.burp.ui.controller.ConfigController;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.SecureCredentialStore;

class ConfigPanelAuthStorageHeadlessTest {

    private final Map<String, String> backing = new ConcurrentHashMap<>();

    @BeforeEach
    void setupStore() {
        MontoyaApiProvider.set(SecureStoreMontoyaMock.create(backing));
    }

    @AfterEach
    void teardownStore() {
        MontoyaApiProvider.set(null);
        backing.clear();
    }

    @Test
    void authDefaultsToNone_thenLoadsSecureBasicValuesOnSelection() throws Exception {
        SecureCredentialStore.saveOpenSearchCredentials("alice", "secret");
        ConfigPanel panel = newPanelOnEdt();
        JComboBox<String> authType = get(panel, "openSearchAuthTypeCombo");
        JTextField user = get(panel, "openSearchUserField");
        JPasswordField pass = get(panel, "openSearchPasswordField");

        runEdt(() -> {
            assertThat(authType.getSelectedItem()).isEqualTo("None");
            assertThat(user.getText()).isBlank();
            assertThat(new String(pass.getPassword())).isBlank();
            authType.setSelectedItem("Basic");
        });

        runEdt(() -> {
            assertThat(user.getText()).isEqualTo("alice");
            assertThat(new String(pass.getPassword())).isEqualTo("secret");
        });
    }

    @Test
    void authenticateAndSaveTooltips_explainSecureHandling() throws Exception {
        ConfigPanel panel = newPanelOnEdt();
        JPanel authForm = get(panel, "openSearchAuthFormPanel");
        JButton authBtn = (JButton) findByName(authForm, "os.authenticate");
        assertThat(authBtn.getToolTipText()).contains("securely").contains("never exported");
    }

    @Test
    void persistSelectedAuthSecrets_persistsBasicCredentialsToSecureStore() throws Exception {
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
}
