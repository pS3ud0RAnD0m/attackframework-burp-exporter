package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import net.miginfocom.swing.MigLayout;

/**
 * Inline OpenSearch authentication and TLS sub-panels extracted from {@link ConfigPanel}.
 */
final class ConfigOpenSearchInlinePanels {

    private ConfigOpenSearchInlinePanels() { }

    record AuthFormResult(JPanel panel, JComboBox<String> authTypeCombo) { }

    record AuthFormFields(
            JTextField userField,
            JPasswordField passwordField,
            JTextField apiKeyIdField,
            JPasswordField apiKeySecretField,
            JTextField jwtTokenField,
            JTextField certPathField,
            JTextField certKeyPathField,
            JPasswordField certPassphraseField) {
    }

    /**
     * Builds the auth-type selector and credential cards shown on the OpenSearch destination row.
     */
    static AuthFormResult buildAuthFormPanel(AuthFormFields fields, Runnable onAuthTypeChanged,
            BooleanSupplier suppressAuthSync) {
        String[] authTypes = { "API Key", "Basic", "Certificate", "JWT", "None" };
        JComboBox<String> authTypeCombo = new Tooltips.HtmlComboBox<>(authTypes);
        authTypeCombo.setName("os.authType");
        authTypeCombo.setSelectedItem("Basic");
        String longest = java.util.Arrays.stream(authTypes)
                .max(java.util.Comparator.comparingInt(value -> value.length()))
                .orElse("Certificate");
        authTypeCombo.setPrototypeDisplayValue(longest);

        JPanel contentCards = new JPanel(new MigLayout("insets 0, hidemode 3", "[left]", "[]"));
        contentCards.setName("os.authContent");

        JPanel noneCard = new JPanel(new MigLayout("insets 0", "[left]", "[]"));
        noneCard.setName("os.authCard.none");

        JPanel basicCard = new JPanel(new MigLayout("insets 0", "[pref][pref][pref][pref][pref]", "[]"));
        basicCard.setName("os.authCard.basic");

        JPanel apiKeyCard = new JPanel(new MigLayout("insets 0", "[pref][pref][pref][pref][pref]", "[]"));
        apiKeyCard.setName("os.authCard.apikey");

        JPanel jwtCard = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[]"));
        jwtCard.setName("os.authCard.jwt");

        JPanel clientCertCard = new JPanel(new MigLayout("insets 0, wrap 2", "[pref][pref]", "[][][]"));
        clientCertCard.setName("os.authCard.certificate");

        contentCards.add(noneCard, "hidemode 3");
        contentCards.add(basicCard, "hidemode 3");
        contentCards.add(apiKeyCard, "hidemode 3");
        contentCards.add(jwtCard, "hidemode 3");
        contentCards.add(clientCertCard, "hidemode 3");

        Consumer<String> applyAuthTypeCardVisibility = selectedType -> {
            noneCard.setVisible("None".equals(selectedType));
            basicCard.setVisible("Basic".equals(selectedType));
            apiKeyCard.setVisible("API Key".equals(selectedType));
            jwtCard.setVisible("JWT".equals(selectedType));
            clientCertCard.setVisible("Certificate".equals(selectedType));
        };

        authTypeCombo.addActionListener(e -> {
            String selectedType = String.valueOf(authTypeCombo.getSelectedItem());
            applyAuthTypeCardVisibility.accept(selectedType);
            if (!suppressAuthSync.getAsBoolean()) {
                onAuthTypeChanged.run();
            }
            contentCards.revalidate();
            contentCards.repaint();
        });
        applyAuthTypeCardVisibility.accept(String.valueOf(authTypeCombo.getSelectedItem()));

        JPanel form = new JPanel(new MigLayout("insets 0", "[pref][pref][grow]", "[]"));
        form.setAlignmentX(Component.LEFT_ALIGNMENT);

        String authTypeTip = Tooltips.html("Select how requests to OpenSearch authenticate.");
        String basicUserTip = Tooltips.html("OpenSearch Basic auth username.", "Stored only within in-process memory.");
        String basicPasswordTip = Tooltips.html("OpenSearch Basic auth password.", "Stored only within in-process memory.");
        String apiKeyIdTip = Tooltips.html("OpenSearch API key ID.", "Stored only within in-process memory.");
        String apiKeySecretTip = Tooltips.html("OpenSearch API key secret.", "Stored only within in-process memory.");
        String jwtTip = Tooltips.html("OpenSearch JWT bearer token.", "Stored only within in-process memory.");
        String certPathTip = Tooltips.html("Path to the client certificate file used for OpenSearch authentication.");
        String keyPathTip = Tooltips.html("Path to the client private key file used for OpenSearch authentication.");
        String passphraseTip = Tooltips.html("Client key passphrase.", "Stored only within in-process memory.");

        Tooltips.apply(authTypeCombo, authTypeTip);
        Tooltips.apply(fields.userField(), basicUserTip);
        Tooltips.apply(fields.passwordField(), basicPasswordTip);
        Tooltips.apply(fields.apiKeyIdField(), apiKeyIdTip);
        Tooltips.apply(fields.apiKeySecretField(), apiKeySecretTip);
        Tooltips.apply(fields.jwtTokenField(), jwtTip);
        Tooltips.apply(fields.certPathField(), certPathTip);
        Tooltips.apply(fields.certKeyPathField(), keyPathTip);
        Tooltips.apply(fields.certPassphraseField(), passphraseTip);

        basicCard.add(Tooltips.label("Username:", basicUserTip));
        basicCard.add(fields.userField(), "gapright 15");
        basicCard.add(Tooltips.label("Password:", basicPasswordTip));
        basicCard.add(fields.passwordField(), "gapright 15");

        apiKeyCard.add(Tooltips.label("Key ID:", apiKeyIdTip));
        apiKeyCard.add(fields.apiKeyIdField(), "gapright 15");
        apiKeyCard.add(Tooltips.label("Key Secret:", apiKeySecretTip));
        apiKeyCard.add(fields.apiKeySecretField(), "gapright 15");

        jwtCard.add(Tooltips.label("JWT Token:", jwtTip));
        jwtCard.add(fields.jwtTokenField(), "w 360!");

        clientCertCard.add(Tooltips.label("Cert Path:", certPathTip));
        clientCertCard.add(fields.certPathField(), "w 360!");
        clientCertCard.add(Tooltips.label("Key Path:", keyPathTip));
        clientCertCard.add(fields.certKeyPathField(), "w 360!");
        clientCertCard.add(Tooltips.label("Passphrase:", passphraseTip));
        clientCertCard.add(fields.certPassphraseField(), "w 360!");

        form.add(Tooltips.label("Auth type:", authTypeTip));
        form.add(authTypeCombo);
        form.add(contentCards, "gapleft 15");

        return new AuthFormResult(form, authTypeCombo);
    }

    record TlsFormFields(
            JComboBox<String> tlsModeCombo,
            JButton importPinnedCertificateButton,
            JCheckBox openSearchSinkCheckbox) {
    }

    /**
     * Builds TLS mode and pinned-certificate import controls for the OpenSearch destination row.
     */
    static JPanel buildTlsPanel(TlsFormFields fields, Consumer<String> onTlsModeSelected) {
        fields.tlsModeCombo().setName("os.tlsMode");
        fields.tlsModeCombo().setSelectedItem("Verify");
        fields.importPinnedCertificateButton().setName("os.tls.import");

        JPanel pinnedPanel = new JPanel(new MigLayout("insets 0", "[pref]", "[]"));
        pinnedPanel.setOpaque(false);
        pinnedPanel.add(fields.importPinnedCertificateButton());

        JPanel controls = new JPanel(new MigLayout("insets 0, hidemode 3", "[pref]", "[]"));
        controls.setOpaque(false);
        controls.add(Box.createHorizontalStrut(0), "hidemode 3");
        controls.add(pinnedPanel, "hidemode 3");

        Consumer<String> applyPinnedVisibility = selectedMode -> {
            boolean pinned = ConfigState.OPEN_SEARCH_TLS_PINNED.equals(normalizeTlsModeLabel(selectedMode));
            pinnedPanel.setVisible(pinned);
            fields.importPinnedCertificateButton().setVisible(pinned);
            fields.importPinnedCertificateButton().setEnabled(fields.openSearchSinkCheckbox().isSelected() && pinned);
        };
        applyPinnedVisibility.accept(String.valueOf(fields.tlsModeCombo().getSelectedItem()));
        fields.tlsModeCombo().addActionListener(e -> {
            String selectedMode = String.valueOf(fields.tlsModeCombo().getSelectedItem());
            onTlsModeSelected.accept(selectedMode);
            applyPinnedVisibility.accept(selectedMode);
            controls.revalidate();
            controls.repaint();
        });

        String tlsModeTip = Tooltips.html(
                "Select how OpenSearch TLS server certificates are trusted.",
                "- Verify: uses the system trust store.",
                "- Trust pinned certificate: requires an imported X.509 server certificate.",
                "- Trust all certificates: disables verification. Use with caution.");
        String importTip = Tooltips.html(
                "Import a pinned X.509 server certificate for OpenSearch TLS trust.",
                "  Common file types: .cer, .crt, .der, .pem.",
                "  The imported certificate bytes and source path are stored only within in-process memory.");
        Tooltips.apply(fields.tlsModeCombo(), tlsModeTip);
        Tooltips.apply(fields.importPinnedCertificateButton(), importTip);

        JPanel form = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[]"));
        form.setOpaque(false);
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(Tooltips.label("TLS mode:", tlsModeTip));
        form.add(fields.tlsModeCombo());
        form.add(controls, "gapleft 12");
        return form;
    }

    static String normalizeTlsModeLabel(String label) {
        if (label == null || label.isBlank()) {
            return ConfigState.OPEN_SEARCH_TLS_VERIFY;
        }
        return switch (label.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "trust pinned certificate" -> ConfigState.OPEN_SEARCH_TLS_PINNED;
            case "trust all certificates" -> ConfigState.OPEN_SEARCH_TLS_INSECURE;
            default -> ConfigState.OPEN_SEARCH_TLS_VERIFY;
        };
    }
}
