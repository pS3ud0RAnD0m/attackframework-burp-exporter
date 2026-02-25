package ai.attackframework.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import burp.api.montoya.MontoyaApi;

/**
 * Ensures {@link MontoyaApiProvider} holds and returns the API instance set by
 * the extension entry point. Clears after each test so other tests are not
 * affected.
 */
class MontoyaApiProviderTest {

    @AfterEach
    void clearProvider() {
        MontoyaApiProvider.set(null);
    }

    @Test
    void get_returnsNull_whenNotSet() {
        MontoyaApiProvider.set(null);
        assertThat(MontoyaApiProvider.get()).isNull();
    }

    @Test
    void get_returnsSetInstance() {
        MontoyaApi api = org.mockito.Mockito.mock(MontoyaApi.class);
        MontoyaApiProvider.set(api);
        assertThat(MontoyaApiProvider.get()).isSameAs(api);
    }

    @Test
    void set_null_clearsProvider() {
        MontoyaApi api = org.mockito.Mockito.mock(MontoyaApi.class);
        MontoyaApiProvider.set(api);
        MontoyaApiProvider.set(null);
        assertThat(MontoyaApiProvider.get()).isNull();
    }
}
