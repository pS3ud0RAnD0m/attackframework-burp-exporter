package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.SecureStoreMontoyaMock;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;

class SecureCredentialStoreTest {

    private final Map<String, String> backing = new ConcurrentHashMap<>();

    private void setupStore() {
        MontoyaApiProvider.set(SecureStoreMontoyaMock.create(backing));
    }

    private void teardownStore() {
        MontoyaApiProvider.set(null);
        backing.clear();
    }

    @Test
    void basic_roundTrip_saveAndLoad() {
        setupStore();
        try {
            SecureCredentialStore.saveOpenSearchCredentials("alice", "secret");
            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("alice");
            assertThat(creds.password()).isEqualTo("secret");
        } finally {
            teardownStore();
        }
    }

    @Test
    void apiKey_roundTrip_saveAndLoad() {
        setupStore();
        try {
            SecureCredentialStore.saveApiKeyCredentials("id-1", "key-1");
            SecureCredentialStore.ApiKeyCredentials creds = SecureCredentialStore.loadApiKeyCredentials();
            assertThat(creds.keyId()).isEqualTo("id-1");
            assertThat(creds.keySecret()).isEqualTo("key-1");
        } finally {
            teardownStore();
        }
    }

    @Test
    void jwt_roundTrip_saveAndLoad() {
        setupStore();
        try {
            SecureCredentialStore.saveJwtCredentials("jwt-token");
            SecureCredentialStore.JwtCredentials creds = SecureCredentialStore.loadJwtCredentials();
            assertThat(creds.token()).isEqualTo("jwt-token");
        } finally {
            teardownStore();
        }
    }

    @Test
    void certificate_roundTrip_saveAndLoad() {
        setupStore();
        try {
            SecureCredentialStore.saveCertificateCredentials("cert.pem", "key.pem", "passphrase");
            SecureCredentialStore.CertificateCredentials creds = SecureCredentialStore.loadCertificateCredentials();
            assertThat(creds.certPath()).isEqualTo("cert.pem");
            assertThat(creds.keyPath()).isEqualTo("key.pem");
            assertThat(creds.passphrase()).isEqualTo("passphrase");
        } finally {
            teardownStore();
        }
    }

    @Test
    void blankInput_clearsOnlyTargetAuthType() {
        setupStore();
        try {
            SecureCredentialStore.saveOpenSearchCredentials("u", "p");
            SecureCredentialStore.saveApiKeyCredentials("id", "sec");
            SecureCredentialStore.saveOpenSearchCredentials("", "");

            SecureCredentialStore.BasicCredentials basic = SecureCredentialStore.loadOpenSearchCredentials();
            SecureCredentialStore.ApiKeyCredentials api = SecureCredentialStore.loadApiKeyCredentials();
            assertThat(basic.username()).isBlank();
            assertThat(basic.password()).isBlank();
            assertThat(api.keyId()).isEqualTo("id");
            assertThat(api.keySecret()).isEqualTo("sec");
        } finally {
            teardownStore();
        }
    }
}
