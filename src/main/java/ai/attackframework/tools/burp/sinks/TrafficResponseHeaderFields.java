package ai.attackframework.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;

import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Traffic-index response header-derived fields stored beside observed response headers.
 */
final class TrafficResponseHeaderFields {

    private static final String CONTENT_TYPE_INFERRED_BURP = "content-type_inferred_burp";
    private static final String CONTENT_TYPE_INFERRED_BURP_BODY = "content-type_inferred_burp_body";

    private TrafficResponseHeaderFields() {}

    static void putInferredContentTypeFields(Map<String, Object> header, HttpResponse response) {
        if (header == null) {
            return;
        }
        MimeType burpDetermined = response == null ? null : response.mimeType();
        MimeType inferredFromBody = response == null ? null : response.inferredMimeType();
        header.put(CONTENT_TYPE_INFERRED_BURP, burpDetermined == null ? null : burpDetermined.name());
        header.put(CONTENT_TYPE_INFERRED_BURP_BODY, inferredFromBody == null ? null : inferredFromBody.name());
    }

    static Map<String, Object> empty() {
        Map<String, Object> header = new LinkedHashMap<>();
        putInferredContentTypeFields(header, null);
        return header;
    }
}
