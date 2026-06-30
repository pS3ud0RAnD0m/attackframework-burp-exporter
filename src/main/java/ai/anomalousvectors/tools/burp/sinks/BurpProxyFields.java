package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Builds {@code burp.proxy.*} edit and history fields for traffic documents.
 */
final class BurpProxyFields {

    private BurpProxyFields() {}

    /**
     * Builds {@code burp.proxy.*} for a Proxy History row.
     *
     * <p>Edit flags come from Montoya plus byte comparison via {@link ProxyEditSupport}.</p>
     *
     * @param item proxy history row
     * @return {@code burp.proxy} sub-document map
     */
    public static Map<String, Object> forProxyHistory(ProxyHttpRequestResponse item) {
        Map<String, Object> proxy = new LinkedHashMap<>();
        proxy.put("history_id", item.id());
        proxy.put("listener_port", item.listenerPort());
        boolean pairEdited = item.edited();
        if (pairEdited) {
            boolean requestEdited = ProxyEditSupport.requestWasEdited(item);
            boolean responseEdited = ProxyEditSupport.responseWasEdited(item);
            if (!requestEdited && !responseEdited) {
                proxy.put("request_is_edited", null);
                proxy.put("response_is_edited", null);
            } else {
                proxy.put("request_is_edited", requestEdited);
                proxy.put("response_is_edited", responseEdited);
            }
        } else {
            proxy.put("request_is_edited", false);
            proxy.put("response_is_edited", false);
        }
        return proxy;
    }

    /**
     * Builds {@code burp.proxy.*} for live HTTP, Repeater tabs, or WebSocket documents.
     *
     * <p>History id is {@code null} and edit flags are unset because these paths are not Proxy History rows.</p>
     *
     * @param listenerPort listener port when known, otherwise {@code null}
     * @return {@code burp.proxy} sub-document map
     */
    public static Map<String, Object> withoutProxyHistoryEditMetadata(Integer listenerPort) {
        Map<String, Object> proxy = new LinkedHashMap<>();
        proxy.put("history_id", null);
        proxy.put("listener_port", listenerPort);
        proxy.put("request_is_edited", null);
        proxy.put("response_is_edited", null);
        return proxy;
    }
}
