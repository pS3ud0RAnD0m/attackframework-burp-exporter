package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SecureCredentialStoreTest {

    @Test
    void basic_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("alice", "secret");
            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("alice");
            assertThat(creds.password()).isEqualTo("secret");
        });
    }

    @Test
    void apiKey_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveApiKeyCredentials("id-1", "key-1");
            SecureCredentialStore.ApiKeyCredentials creds = SecureCredentialStore.loadApiKeyCredentials();
            assertThat(creds.keyId()).isEqualTo("id-1");
            assertThat(creds.keySecret()).isEqualTo("key-1");
        });
    }

    @Test
    void jwt_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveJwtCredentials("jwt-token");
            SecureCredentialStore.JwtCredentials creds = SecureCredentialStore.loadJwtCredentials();
            assertThat(creds.token()).isEqualTo("jwt-token");
        });
    }

    @Test
    void certificate_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveCertificateCredentials("cert.pem", "key.pem", "passphrase");
            SecureCredentialStore.CertificateCredentials creds = SecureCredentialStore.loadCertificateCredentials();
            assertThat(creds.certPath()).isEqualTo("cert.pem");
            assertThat(creds.keyPath()).isEqualTo("key.pem");
            assertThat(creds.passphrase()).isEqualTo("passphrase");
        });
    }

    @Test
    void blankInput_clearsOnlyTargetAuthType() {
        withCleanStore(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("u", "p");
            SecureCredentialStore.saveApiKeyCredentials("id", "sec");
            SecureCredentialStore.saveOpenSearchCredentials("", "");

            SecureCredentialStore.BasicCredentials basic = SecureCredentialStore.loadOpenSearchCredentials();
            SecureCredentialStore.ApiKeyCredentials api = SecureCredentialStore.loadApiKeyCredentials();
            assertThat(basic.username()).isBlank();
            assertThat(basic.password()).isBlank();
            assertThat(api.keyId()).isEqualTo("id");
            assertThat(api.keySecret()).isEqualTo("sec");
        });
    }

    @Test
    void clearAll_resets_session_values() {
        withCleanStore(() -> {
            SecureCredentialStore.saveSelectedAuthType("JWT");
            SecureCredentialStore.saveOpenSearchCredentials("u", "p");
            SecureCredentialStore.saveJwtCredentials("jwt-token");

            SecureCredentialStore.clearAll();

            assertThat(SecureCredentialStore.loadSelectedAuthType()).isEqualTo("Basic");
            assertThat(SecureCredentialStore.loadOpenSearchCredentials().username()).isBlank();
            assertThat(SecureCredentialStore.loadJwtCredentials().token()).isBlank();
        });
    }

    private static void withCleanStore(CheckedRunnable action) {
        SecureCredentialStore.clearAll();
        try {
            action.run();
        } finally {
            SecureCredentialStore.clearAll();
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run();
    }
}
