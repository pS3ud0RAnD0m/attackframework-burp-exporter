package ai.attackframework.tools.burp.utils.config;

/**
 * Stores OpenSearch credentials in memory for the current Burp session only.
 */
public final class SecureCredentialStore {
    private static volatile String selectedAuthType = "Basic";
    private static volatile BasicCredentials basicCredentials = new BasicCredentials("", "");
    private static volatile ApiKeyCredentials apiKeyCredentials = new ApiKeyCredentials("", "");
    private static volatile JwtCredentials jwtCredentials = new JwtCredentials("");
    private static volatile CertificateCredentials certificateCredentials = new CertificateCredentials("", "", "");
    private static volatile PinnedTlsCertificate pinnedTlsCertificate = new PinnedTlsCertificate("", "", new byte[0]);

    private SecureCredentialStore() {}

    /** Immutable basic credentials pair read from session memory. */
    public record BasicCredentials(String username, String password) {}
    /** Immutable API key credentials pair read from session memory. */
    public record ApiKeyCredentials(String keyId, String keySecret) {}
    /** Immutable JWT token credentials read from session memory. */
    public record JwtCredentials(String token) {}
    /** Immutable certificate credentials read from session memory. */
    public record CertificateCredentials(String certPath, String keyPath, String passphrase) {}
    /** Immutable imported TLS pin material read from session memory. */
    public record PinnedTlsCertificate(String sourcePath, String fingerprintSha256, byte[] encodedBytes) {}

    /** Saves selected auth type for the current Burp session. */
    public static void saveSelectedAuthType(String authType) {
        selectedAuthType = normalizeAuthType(authType);
    }

    /** Loads selected auth type for the current Burp session. */
    public static String loadSelectedAuthType() {
        return normalizeAuthType(selectedAuthType);
    }

    /** Saves basic credentials for the current Burp session. Blank values clear stored credentials. */
    public static void saveOpenSearchCredentials(String username, String password) {
        String user = safe(username);
        String pass = safe(password);
        if (user.isBlank() || pass.isBlank()) {
            clearOpenSearchCredentials();
            return;
        }
        basicCredentials = new BasicCredentials(user, pass);
    }

    /** Loads basic credentials for the current Burp session. */
    public static BasicCredentials loadOpenSearchCredentials() {
        return basicCredentials;
    }

    /** Saves API key credentials for the current Burp session. */
    public static void saveApiKeyCredentials(String keyId, String keySecret) {
        String id = safe(keyId);
        String secret = safe(keySecret);
        if (id.isBlank() || secret.isBlank()) {
            clearApiKeyCredentials();
            return;
        }
        apiKeyCredentials = new ApiKeyCredentials(id, secret);
    }

    /** Loads API key credentials for the current Burp session. */
    public static ApiKeyCredentials loadApiKeyCredentials() {
        return apiKeyCredentials;
    }

    /** Saves JWT credentials for the current Burp session. */
    public static void saveJwtCredentials(String token) {
        String jwt = safe(token);
        if (jwt.isBlank()) {
            clearJwtCredentials();
            return;
        }
        jwtCredentials = new JwtCredentials(jwt);
    }

    /** Loads JWT credentials for the current Burp session. */
    public static JwtCredentials loadJwtCredentials() {
        return jwtCredentials;
    }

    /** Saves certificate credentials for the current Burp session. */
    public static void saveCertificateCredentials(String certPath, String keyPath, String passphrase) {
        String cert = safe(certPath);
        String key = safe(keyPath);
        String pass = safe(passphrase);
        if (cert.isBlank() || key.isBlank()) {
            clearCertificateCredentials();
            return;
        }
        certificateCredentials = new CertificateCredentials(cert, key, pass);
    }

    /** Loads certificate credentials for the current Burp session. */
    public static CertificateCredentials loadCertificateCredentials() {
        return certificateCredentials;
    }

    /** Saves pinned TLS certificate material for the current Burp session. */
    public static void savePinnedTlsCertificate(String sourcePath, String fingerprintSha256, byte[] encodedBytes) {
        String path = safe(sourcePath);
        String fingerprint = safe(fingerprintSha256);
        byte[] bytes = encodedBytes == null ? new byte[0] : java.util.Arrays.copyOf(encodedBytes, encodedBytes.length);
        if (path.isBlank() || fingerprint.isBlank() || bytes.length == 0) {
            clearPinnedTlsCertificate();
            return;
        }
        pinnedTlsCertificate = new PinnedTlsCertificate(path, fingerprint, bytes);
    }

    /** Loads pinned TLS certificate material for the current Burp session. */
    public static PinnedTlsCertificate loadPinnedTlsCertificate() {
        PinnedTlsCertificate current = pinnedTlsCertificate;
        return new PinnedTlsCertificate(current.sourcePath(), current.fingerprintSha256(),
                java.util.Arrays.copyOf(current.encodedBytes(), current.encodedBytes().length));
    }

    /** Clears basic credentials for the current Burp session. */
    public static void clearOpenSearchCredentials() {
        basicCredentials = new BasicCredentials("", "");
    }

    /** Clears API key credentials for the current Burp session. */
    public static void clearApiKeyCredentials() {
        apiKeyCredentials = new ApiKeyCredentials("", "");
    }

    /** Clears JWT credentials for the current Burp session. */
    public static void clearJwtCredentials() {
        jwtCredentials = new JwtCredentials("");
    }

    /** Clears certificate credentials for the current Burp session. */
    public static void clearCertificateCredentials() {
        certificateCredentials = new CertificateCredentials("", "", "");
    }

    /** Clears pinned TLS certificate material for the current Burp session. */
    public static void clearPinnedTlsCertificate() {
        pinnedTlsCertificate = new PinnedTlsCertificate("", "", new byte[0]);
    }

    /** Clears all session-scoped auth values. Intended for tests and extension reload/reset paths. */
    public static void clearAll() {
        selectedAuthType = "Basic";
        clearOpenSearchCredentials();
        clearApiKeyCredentials();
        clearJwtCredentials();
        clearCertificateCredentials();
        clearPinnedTlsCertificate();
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizeAuthType(String authType) {
        if (authType == null || authType.isBlank()) {
            return "None";
        }
        return switch (authType.trim().toLowerCase()) {
            case "basic" -> "Basic";
            case "api key", "apikey" -> "API Key";
            case "jwt" -> "JWT";
            case "certificate", "cert" -> "Certificate";
            default -> "None";
        };
    }
}

