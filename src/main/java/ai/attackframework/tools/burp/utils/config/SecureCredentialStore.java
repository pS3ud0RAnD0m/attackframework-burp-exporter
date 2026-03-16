package ai.attackframework.tools.burp.utils.config;

import java.lang.reflect.Method;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;

/**
 * Stores OpenSearch credentials in Burp's Montoya-backed persistence store.
 *
 * <p>This keeps credentials out of plain-text config payloads used for normal config
 * serialization flows. Values are namespaced and loaded opportunistically when the
 * extension starts.</p>
 */
public final class SecureCredentialStore {

    private static final String KEY_AUTH_TYPE = "attackframework.opensearch.auth.type";
    private static final String KEY_BASIC_USER = "attackframework.opensearch.auth.basic.user";
    private static final String KEY_BASIC_PASS = "attackframework.opensearch.auth.basic.pass";
    private static final String KEY_API_KEY_ID = "attackframework.opensearch.auth.apikey.id";
    private static final String KEY_API_KEY_SECRET = "attackframework.opensearch.auth.apikey.secret";
    private static final String KEY_JWT_TOKEN = "attackframework.opensearch.auth.jwt.token";
    private static final String KEY_CERT_PATH = "attackframework.opensearch.auth.cert.path";
    private static final String KEY_CERT_KEY_PATH = "attackframework.opensearch.auth.cert.keyPath";
    private static final String KEY_CERT_PASSPHRASE = "attackframework.opensearch.auth.cert.passphrase";

    private SecureCredentialStore() {}

    /** Immutable basic credentials pair read from secure storage. */
    public record BasicCredentials(String username, String password) {}
    /** Immutable API key credentials pair read from secure storage. */
    public record ApiKeyCredentials(String keyId, String keySecret) {}
    /** Immutable JWT token credentials read from secure storage. */
    public record JwtCredentials(String token) {}
    /** Immutable certificate credentials read from secure storage. */
    public record CertificateCredentials(String certPath, String keyPath, String passphrase) {}

    /** Saves selected auth type to secure storage. */
    public static void saveSelectedAuthType(String authType) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        String normalized = normalizeAuthType(authType);
        invokeSetString(store, KEY_AUTH_TYPE, normalized);
    }

    /** Loads selected auth type from secure storage. Defaults to None when unavailable. */
    public static String loadSelectedAuthType() {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return "None";
        }
        return normalizeAuthType(invokeGetString(store, KEY_AUTH_TYPE));
    }

    /** Saves basic credentials to Montoya persistence. Blank values clear stored credentials. */
    public static void saveOpenSearchCredentials(String username, String password) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        String user = safe(username);
        String pass = safe(password);
        if (user.isBlank() || pass.isBlank()) {
            clearOpenSearchCredentials();
            return;
        }
        invokeSetString(store, KEY_BASIC_USER, user);
        invokeSetString(store, KEY_BASIC_PASS, pass);
    }

    /** Loads basic credentials from Montoya persistence, returning blanks if unavailable. */
    public static BasicCredentials loadOpenSearchCredentials() {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return new BasicCredentials("", "");
        }
        String user = safe(invokeGetString(store, KEY_BASIC_USER));
        String pass = safe(invokeGetString(store, KEY_BASIC_PASS));
        return new BasicCredentials(user, pass);
    }

    /** Saves API key credentials. Blank values clear stored values for this auth type. */
    public static void saveApiKeyCredentials(String keyId, String keySecret) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        String id = safe(keyId);
        String secret = safe(keySecret);
        if (id.isBlank() || secret.isBlank()) {
            clearApiKeyCredentials();
            return;
        }
        invokeSetString(store, KEY_API_KEY_ID, id);
        invokeSetString(store, KEY_API_KEY_SECRET, secret);
    }

    /** Loads API key credentials from secure storage. */
    public static ApiKeyCredentials loadApiKeyCredentials() {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return new ApiKeyCredentials("", "");
        }
        return new ApiKeyCredentials(
                safe(invokeGetString(store, KEY_API_KEY_ID)),
                safe(invokeGetString(store, KEY_API_KEY_SECRET)));
    }

    /** Saves JWT credentials. Blank token clears stored value. */
    public static void saveJwtCredentials(String token) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        String jwt = safe(token);
        if (jwt.isBlank()) {
            clearJwtCredentials();
            return;
        }
        invokeSetString(store, KEY_JWT_TOKEN, jwt);
    }

    /** Loads JWT credentials from secure storage. */
    public static JwtCredentials loadJwtCredentials() {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return new JwtCredentials("");
        }
        return new JwtCredentials(safe(invokeGetString(store, KEY_JWT_TOKEN)));
    }

    /** Saves certificate credentials. Blank path values clear stored certificate values. */
    public static void saveCertificateCredentials(String certPath, String keyPath, String passphrase) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        String cert = safe(certPath);
        String key = safe(keyPath);
        String pass = safe(passphrase);
        if (cert.isBlank() || key.isBlank()) {
            clearCertificateCredentials();
            return;
        }
        invokeSetString(store, KEY_CERT_PATH, cert);
        invokeSetString(store, KEY_CERT_KEY_PATH, key);
        invokeSetString(store, KEY_CERT_PASSPHRASE, pass);
    }

    /** Loads certificate credentials from secure storage. */
    public static CertificateCredentials loadCertificateCredentials() {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return new CertificateCredentials("", "", "");
        }
        return new CertificateCredentials(
                safe(invokeGetString(store, KEY_CERT_PATH)),
                safe(invokeGetString(store, KEY_CERT_KEY_PATH)),
                safe(invokeGetString(store, KEY_CERT_PASSPHRASE)));
    }

    /** Clears stored OpenSearch credentials from Montoya persistence. */
    public static void clearOpenSearchCredentials() {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        if (!invokeDeleteString(store, KEY_BASIC_USER)) {
            invokeSetString(store, KEY_BASIC_USER, "");
        }
        if (!invokeDeleteString(store, KEY_BASIC_PASS)) {
            invokeSetString(store, KEY_BASIC_PASS, "");
        }
    }

    /** Clears stored API key credentials from secure storage. */
    public static void clearApiKeyCredentials() {
        clearPair(KEY_API_KEY_ID, KEY_API_KEY_SECRET);
    }

    /** Clears stored JWT credentials from secure storage. */
    public static void clearJwtCredentials() {
        clearOne(KEY_JWT_TOKEN);
    }

    /** Clears stored certificate credentials from secure storage. */
    public static void clearCertificateCredentials() {
        clearOne(KEY_CERT_PATH);
        clearOne(KEY_CERT_KEY_PATH);
        clearOne(KEY_CERT_PASSPHRASE);
    }

    private static Object resolveMontoyaStore() {
        Object api = MontoyaApiProvider.get();
        if (api == null) {
            return null;
        }
        Object persistence = invokeNoArg(api, "persistence");
        if (persistence == null) {
            return null;
        }
        Object extensionData = invokeNoArg(persistence, "extensionData");
        if (extensionData != null) {
            return extensionData;
        }
        return invokeNoArg(persistence, "preferences");
    }

    private static Object invokeNoArg(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            return m.invoke(target);
        } catch (ReflectiveOperationException | SecurityException e) {
            return null;
        }
    }

    private static void invokeSetString(Object store, String key, String value) {
        try {
            Method m = store.getClass().getMethod("setString", String.class, String.class);
            m.invoke(store, key, value);
        } catch (ReflectiveOperationException | SecurityException e) {
            Logger.logDebug("[Config] secure-store setString unavailable: " + e.getClass().getSimpleName());
        }
    }

    private static String invokeGetString(Object store, String key) {
        try {
            Method m = store.getClass().getMethod("getString", String.class);
            Object value = m.invoke(store, key);
            return value instanceof String s ? s : "";
        } catch (ReflectiveOperationException | SecurityException e) {
            return "";
        }
    }

    private static boolean invokeDeleteString(Object store, String key) {
        try {
            Method m = store.getClass().getMethod("deleteString", String.class);
            m.invoke(store, key);
            return true;
        } catch (ReflectiveOperationException | SecurityException e) {
            return false;
        }
    }

    private static void clearPair(String keyA, String keyB) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        if (!invokeDeleteString(store, keyA)) {
            invokeSetString(store, keyA, "");
        }
        if (!invokeDeleteString(store, keyB)) {
            invokeSetString(store, keyB, "");
        }
    }

    private static void clearOne(String key) {
        Object store = resolveMontoyaStore();
        if (store == null) {
            return;
        }
        if (!invokeDeleteString(store, key)) {
            invokeSetString(store, key, "");
        }
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

