package ai.attackframework.tools.burp.utils.concurrent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scope.Scope;

/**
 * Unit tests for {@link SnapshotScopeCache} URL memoization.
 */
class SnapshotScopeCacheTest {

    @Test
    void isInScope_cachesRepeatedLookups() {
        MontoyaApi api = mock(MontoyaApi.class);
        Scope scope = mock(Scope.class);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope("https://example.com/")).thenReturn(true);

        SnapshotScopeCache cache = new SnapshotScopeCache(api);

        assertThat(cache.isInScope("https://example.com/")).isTrue();
        assertThat(cache.isInScope("https://example.com/")).isTrue();
        verify(scope, times(1)).isInScope("https://example.com/");
    }

    @Test
    void isInScope_blankUrl_returnsFalseWithoutCallingBurp() {
        MontoyaApi api = mock(MontoyaApi.class);
        SnapshotScopeCache cache = new SnapshotScopeCache(api);

        assertThat(cache.isInScope("")).isFalse();
        assertThat(cache.isInScope("   ")).isFalse();
        verify(api, times(0)).scope();
    }
}
