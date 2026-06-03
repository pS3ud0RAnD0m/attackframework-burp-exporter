package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

class BurpProxyFieldsTest {

    @Test
    void forProxyHistory_whenNotEdited_setsSideFlagsFalse() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.id()).thenReturn(42);
        when(item.listenerPort()).thenReturn(8080);
        when(item.edited()).thenReturn(false);

        Map<String, Object> proxy = BurpProxyFields.forProxyHistory(item);

        assertThat(proxy.get("history_id")).isEqualTo(42);
        assertThat(proxy.get("listener_port")).isEqualTo(8080);
        assertThat(proxy).doesNotContainKey("is_edited");
        assertThat(proxy.get("request_is_edited")).isEqualTo(false);
        assertThat(proxy.get("response_is_edited")).isEqualTo(false);
    }

    @Test
    void forProxyHistory_whenEditedButBytesDoNotIdentifySide_setsSideFlagsNull() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.id()).thenReturn(7);
        when(item.listenerPort()).thenReturn(443);
        when(item.edited()).thenReturn(true);
        when(item.finalRequest()).thenReturn(null);
        when(item.request()).thenReturn(null);
        when(item.hasResponse()).thenReturn(false);

        Map<String, Object> proxy = BurpProxyFields.forProxyHistory(item);

        assertThat(proxy).doesNotContainKey("is_edited");
        assertThat(proxy.get("request_is_edited")).isNull();
        assertThat(proxy.get("response_is_edited")).isNull();
    }

    @Test
    void forProxyHistory_whenEdited_setsSideFlagsFromByteComparison() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpRequest sent = mock(HttpRequest.class);
        HttpRequest stored = mock(HttpRequest.class);
        ByteArray sentBytes = mock(ByteArray.class);
        ByteArray storedBytes = mock(ByteArray.class);
        when(item.id()).thenReturn(3);
        when(item.listenerPort()).thenReturn(8080);
        when(item.edited()).thenReturn(true);
        when(item.finalRequest()).thenReturn(sent);
        when(item.request()).thenReturn(stored);
        when(item.hasResponse()).thenReturn(false);
        when(sent.toByteArray()).thenReturn(sentBytes);
        when(stored.toByteArray()).thenReturn(storedBytes);
        when(sentBytes.getBytes()).thenReturn(new byte[] { 1 });
        when(storedBytes.getBytes()).thenReturn(new byte[] { 2 });

        Map<String, Object> proxy = BurpProxyFields.forProxyHistory(item);

        assertThat(proxy.get("request_is_edited")).isEqualTo(true);
        assertThat(proxy.get("response_is_edited")).isEqualTo(false);
    }

    @Test
    void withoutProxyHistoryEditMetadata_setsNullEditFlags() {
        Map<String, Object> proxy = BurpProxyFields.withoutProxyHistoryEditMetadata(9090);

        assertThat(proxy.get("history_id")).isNull();
        assertThat(proxy.get("listener_port")).isEqualTo(9090);
        assertThat(proxy).doesNotContainKey("is_edited");
        assertThat(proxy.get("request_is_edited")).isNull();
        assertThat(proxy.get("response_is_edited")).isNull();
    }
}
