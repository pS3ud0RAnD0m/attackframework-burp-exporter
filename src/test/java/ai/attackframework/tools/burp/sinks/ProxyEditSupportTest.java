package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

class ProxyEditSupportTest {

    @Test
    void requestWasEdited_whenRequestBytesDiffer_returnsTrue() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpRequest sent = mock(HttpRequest.class);
        HttpRequest stored = mock(HttpRequest.class);
        ByteArray sentBytes = mock(ByteArray.class);
        ByteArray storedBytes = mock(ByteArray.class);
        when(item.edited()).thenReturn(true);
        when(item.finalRequest()).thenReturn(sent);
        when(item.request()).thenReturn(stored);
        when(sent.toByteArray()).thenReturn(sentBytes);
        when(stored.toByteArray()).thenReturn(storedBytes);
        when(sentBytes.getBytes()).thenReturn(new byte[] { 1 });
        when(storedBytes.getBytes()).thenReturn(new byte[] { 2 });

        assertThat(ProxyEditSupport.requestWasEdited(item)).isTrue();
    }

    @Test
    void responseWasEdited_whenResponseBytesDiffer_returnsTrue() {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpResponse effective = mock(HttpResponse.class);
        HttpResponse original = mock(HttpResponse.class);
        ByteArray effectiveBytes = mock(ByteArray.class);
        ByteArray originalBytes = mock(ByteArray.class);
        when(item.edited()).thenReturn(true);
        when(item.hasResponse()).thenReturn(true);
        when(item.response()).thenReturn(effective);
        when(item.originalResponse()).thenReturn(original);
        when(effective.toByteArray()).thenReturn(effectiveBytes);
        when(original.toByteArray()).thenReturn(originalBytes);
        when(effectiveBytes.getBytes()).thenReturn(new byte[] { 9 });
        when(originalBytes.getBytes()).thenReturn(new byte[] { 8 });

        assertThat(ProxyEditSupport.responseWasEdited(item)).isTrue();
    }
}
