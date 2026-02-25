package ai.attackframework.tools.burp.utils;

import burp.api.montoya.MontoyaApi;

/**
 * Holder for the Montoya API instance provided at extension load.
 * Set in {@link ai.attackframework.tools.burp.Exporter#initialize}; used by
 * components that need Burp APIs (e.g. settings export) without receiving the
 * API through the UI hierarchy.
 */
public final class MontoyaApiProvider {

    private static volatile MontoyaApi api;

    private MontoyaApiProvider() {}

    /** Sets the API handle. Called once from the extension entry point. */
    public static void set(MontoyaApi montoyaApi) {
        api = montoyaApi;
    }

    /** Returns the current API handle, or null if not set (e.g. in tests). */
    public static MontoyaApi get() {
        return api;
    }
}
