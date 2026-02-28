package ai.attackframework.tools.burp.utils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;

/**
 * Unit tests for {@link ScopeFilter} scope logic (all, burp, custom with string/regex entries).
 */
class ScopeFilterTest {

    private static ConfigState.State state(String scopeType, List<ConfigState.ScopeEntry> custom) {
        return new ConfigState.State(
                List.of(),
                scopeType,
                custom == null ? List.of() : custom,
                new ConfigState.Sinks(false, "", false, ""),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES
        );
    }

    @Test
    void shouldExport_nullState_returnsFalse() {
        assertThat(ScopeFilter.shouldExport(null, "https://example.com/", true)).isFalse();
    }

    @Test
    void shouldExport_scopeAll_returnsTrueRegardlessOfBurpOrUrl() {
        ConfigState.State state = state(ConfigKeys.SCOPE_ALL, null);
        assertThat(ScopeFilter.shouldExport(state, "https://example.com/", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "https://example.com/", false)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, null, false)).isTrue();
    }

    @Test
    void shouldExport_scopeBurp_delegatesToBurpInScope() {
        ConfigState.State state = state(ConfigKeys.SCOPE_BURP, null);
        assertThat(ScopeFilter.shouldExport(state, "https://example.com/", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "https://example.com/", false)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_nullUrl_returnsFalse() {
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("example", ConfigState.Kind.STRING)));
        assertThat(ScopeFilter.shouldExport(state, null, true)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_stringMatch_returnsTrue() {
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("acme.com", ConfigState.Kind.STRING)));
        assertThat(ScopeFilter.shouldExport(state, "https://acme.com/path", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "https://sub.acme.com/", true)).isTrue();
    }

    @Test
    void shouldExport_scopeCustom_stringMatchesHost_notFullUrl() {
        // STRING is matched against the host only (same as REGEX), so "acme.com" matches host acme.com.
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("acme.com", ConfigState.Kind.STRING)));
        assertThat(ScopeFilter.shouldExport(state, "https://acme.com/foo?param1=value1", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "https://acme2.com/", true)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_stringNoMatch_returnsFalse() {
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("acme.com", ConfigState.Kind.STRING)));
        assertThat(ScopeFilter.shouldExport(state, "https://other.com/", true)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_regexMatch_returnsTrue() {
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry(".*acme\\.com.*", ConfigState.Kind.REGEX)));
        assertThat(ScopeFilter.shouldExport(state, "https://acme.com/path", true)).isTrue();
    }

    @Test
    void shouldExport_scopeCustom_regexHostAnchors_matchesHostOnly() {
        // REGEX is matched against the URL host, so ^.*acme\.com$ matches acme.com but not acme2.com.
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("^.*acme\\.com$", ConfigState.Kind.REGEX)));
        assertThat(ScopeFilter.shouldExport(state, "https://acme.com/foo?param1=value1", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "https://sub.acme.com/bar", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "https://acme2.com/", true)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_regexNoMatch_returnsFalse() {
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(new ConfigState.ScopeEntry("^https://acme\\.com$", ConfigState.Kind.REGEX)));
        assertThat(ScopeFilter.shouldExport(state, "https://other.com/", true)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_emptyEntries_returnsFalse() {
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM, List.of());
        assertThat(ScopeFilter.shouldExport(state, "https://example.com/", true)).isFalse();
    }

    @Test
    void shouldExport_scopeCustom_normalizesCase_andAppliesCustomEntries() {
        // Scope type "Custom" (capital C) is normalized to "custom" so custom logic runs; otherwise default -> true would export all.
        ConfigState.State state = state("Custom",
                List.of(new ConfigState.ScopeEntry("acme.com", ConfigState.Kind.STRING)));
        assertThat(ScopeFilter.shouldExport(state, "https://other.com/", true)).isFalse();
        assertThat(ScopeFilter.shouldExport(state, "https://acme.com/path", true)).isTrue();
    }

    @Test
    void shouldExport_scopeCustom_fallsBackToFullUrl_whenNoParseableHost() {
        // URL with no scheme/host (e.g. opaque or relative) falls back to full string for STRING/REGEX.
        ConfigState.State state = state(ConfigKeys.SCOPE_CUSTOM,
                List.of(
                        new ConfigState.ScopeEntry("acme", ConfigState.Kind.STRING),
                        new ConfigState.ScopeEntry("^acme\\.com$", ConfigState.Kind.REGEX)
                ));
        assertThat(ScopeFilter.shouldExport(state, "acme.com", true)).isTrue();
        assertThat(ScopeFilter.shouldExport(state, "other.com", true)).isFalse();
    }
}
