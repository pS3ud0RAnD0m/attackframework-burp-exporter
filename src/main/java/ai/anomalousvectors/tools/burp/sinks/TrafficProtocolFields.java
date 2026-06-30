package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Traffic-index {@code request.protocol} and {@code response.protocol} sub-documents.
 */
final class TrafficProtocolFields {

    private TrafficProtocolFields() {}

    static Map<String, Object> requestProtocol(String httpVersion) {
        Map<String, Object> protocol = new LinkedHashMap<>();
        protocol.put("http_version", httpVersion);
        return protocol;
    }

    static Map<String, Object> responseProtocol(String httpVersion) {
        Map<String, Object> protocol = new LinkedHashMap<>();
        protocol.put("http_version", httpVersion);
        return protocol;
    }
}
