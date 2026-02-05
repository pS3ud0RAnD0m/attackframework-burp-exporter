package ai.attackframework.tools.burp.utils;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;

/**
 * Decides whether a URL is in scope for export based on the extension's scope configuration.
 *
 * <p>Used by traffic and other exporters to skip out-of-scope items. Not thread-safe when
 * state is mutated elsewhere; callers typically pass a snapshot from {@link
 * ai.attackframework.tools.burp.utils.config.RuntimeConfig#getState()}.</p>
 *
 * <p>Scope type is normalized to lowercase and trimmed so that {@code "Custom"} and
 * {@code "custom"} are treated identically.</p>
 */
public final class ScopeFilter {

    private ScopeFilter() { }

    /**
     * Returns whether the given request should be exported according to the current scope.
     *
     * <p>Scope type "all" exports everything; "burp" uses Burp's in-scope flag; "custom"
     * matches the URL against custom regex/string entries (any match includes the URL).
     * Scope type is normalized to lowercase before comparison.</p>
     *
     * @param state       current config state; {@code null} is treated as no export
     * @param url         full request URL to test; {@code null} is treated as out of scope
     * @param burpInScope Burp's {@code request.isInScope()} result; used only when
     *                    {@code state.scopeType()} is {@link ConfigKeys#SCOPE_BURP}
     * @return {@code true} if the request is in scope and should be exported
     */
    public static boolean shouldExport(ConfigState.State state, String url, boolean burpInScope) {
        if (state == null) {
            Logger.logTrace("[ScopeFilter] state is null -> shouldExport=false");
            return false;
        }
        String raw = state.scopeType();
        String scopeType = (raw == null || raw.isBlank())
                ? ConfigKeys.SCOPE_ALL
                : raw.trim().toLowerCase(Locale.ROOT);

        boolean result;
        switch (scopeType) {
            case ConfigKeys.SCOPE_BURP:
                result = burpInScope;
                Logger.logTrace("[ScopeFilter] scope=burp burpInScope=" + burpInScope + " -> shouldExport=" + result);
                break;
            case ConfigKeys.SCOPE_CUSTOM:
                List<ConfigState.ScopeEntry> entries = state.customEntries();
                result = url != null && matchesCustom(url, entries);
                Logger.logDebug("[ScopeFilter] scope=custom url=" + truncateForLog(url, 80)
                        + " customEntries=" + (entries != null ? entries.size() : 0)
                        + " -> shouldExport=" + result);
                break;
            default:
                Logger.logTrace("[ScopeFilter] scope=\"" + scopeType + "\" (treated as all) -> shouldExport=true");
                result = true;
                break;
        }
        return result;
    }

    /** Truncates string for log output to avoid huge URLs in logs. */
    private static String truncateForLog(String s, int maxLen) {
        if (s == null) return "null";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }

    /**
     * Returns whether the URL matches any custom scope entry.
     *
     * <p>Both STRING and REGEX entries are matched against the URL's <em>host</em> (authority host).
     * STRING uses substring containment; REGEX uses {@link Pattern#compile(String)} and
     * {@link java.util.regex.Matcher#find()}. So {@code acme.com} STRING and {@code ^.*acme\.com$}
     * REGEX both match {@code https://acme.com/foo?param=value}. If the URL has no parseable host,
     * the full URL is used. Invalid regex entries are skipped.</p>
     *
     * @param url     non-null URL string
     * @param entries custom scope entries; {@code null} or empty yields {@code false}
     * @return {@code true} if at least one entry matches
     */
    private static boolean matchesCustom(String url, List<ConfigState.ScopeEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            Logger.logTrace("[ScopeFilter] custom entries null or empty -> no match");
            return false;
        }
        String target = hostFromUrl(url);
        if (target == null) target = url;

        for (ConfigState.ScopeEntry e : entries) {
            String value = e.value();
            if (value == null || value.isBlank()) {
                Logger.logTrace("[ScopeFilter] skipping blank entry");
                continue;
            }
            boolean matched;
            if (e.kind() == ConfigState.Kind.STRING) {
                matched = target.contains(value);
                Logger.logTrace("[ScopeFilter] STRING entry \"" + truncateForLog(value, 40)
                        + "\" against host \"" + truncateForLog(target, 60) + "\" contains? " + matched);
                if (matched) return true;
            } else {
                try {
                    matched = Pattern.compile(value).matcher(target).find();
                    Logger.logTrace("[ScopeFilter] REGEX entry \"" + truncateForLog(value, 40)
                            + "\" against host \"" + truncateForLog(target, 60) + "\" find? " + matched);
                    if (matched) return true;
                } catch (Exception ex) {
                    Logger.logTrace("[ScopeFilter] REGEX entry invalid, skipping: " + ex.getMessage());
                }
            }
        }
        Logger.logTrace("[ScopeFilter] no custom entry matched");
        return false;
    }

    /**
     * Extracts the host (authority host) from a URL for custom scope matching (STRING and REGEX).
     *
     * @param url full URL; may be {@code null} or blank
     * @return host string, or {@code null} if unparseable or no host
     */
    private static String hostFromUrl(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            URI uri = URI.create(url);
            return uri.getHost();
        } catch (Exception ignored) {
            return null;
        }
    }
}
