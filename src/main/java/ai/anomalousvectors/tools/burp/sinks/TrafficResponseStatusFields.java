package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;

import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Traffic-index {@code response.status} sub-document.
 */
final class TrafficResponseStatusFields {

    private TrafficResponseStatusFields() {}

    static Map<String, Object> from(HttpResponse response) {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("code", (int) response.statusCode());
        status.put("code_class", RequestResponseDocBuilder.statusCodeClassName(response.statusCode()));
        status.put("description", response.reasonPhrase());
        return status;
    }

    static Map<String, Object> of(int code, String codeClass, String description) {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("code", code);
        status.put("code_class", codeClass);
        status.put("description", description);
        return status;
    }
}
