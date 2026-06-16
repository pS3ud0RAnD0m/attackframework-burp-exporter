package ai.attackframework.tools.burp.utils.concurrent;

import java.util.concurrent.ConcurrentHashMap;

import burp.api.montoya.MontoyaApi;

/**
 * Per-snapshot URL to Burp scope cache safe for parallel document builders.
 */
public final class SnapshotScopeCache {

    private final MontoyaApi api;
    private final ConcurrentHashMap<String, Boolean> inScopeByUrl = new ConcurrentHashMap<>();

    public SnapshotScopeCache(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Returns whether {@code url} is in Burp scope, caching positive and negative answers.
     */
    public boolean isInScope(String url) {
        if (url == null || url.isBlank() || api == null) {
            return false;
        }
        return inScopeByUrl.computeIfAbsent(url, this::lookupScope);
    }

    private boolean lookupScope(String url) {
        try {
            var scope = api.scope();
            return scope != null && scope.isInScope(url);
        } catch (RuntimeException ignored) {
            return false;
        }
    }
}
