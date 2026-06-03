package ai.attackframework.tools.burp.sinks;

import java.util.List;
import java.util.Map;

import ai.attackframework.tools.burp.utils.StringKeyedMaps;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;

final class TrafficPairMarkers {

    private TrafficPairMarkers() {}

    static void overlayPairMarkers(
            Map<String, Object> requestDoc, Map<String, Object> responseDoc, HttpRequestResponse pair) {
        try {
            List<Marker> requestMarkers = pair == null ? List.of() : pair.requestMarkers();
            if (requestMarkers != null && !requestMarkers.isEmpty()) {
                putBodyMarkers(requestDoc, RequestResponseDocBuilder.convertTrafficMarkersToList(requestMarkers));
            }
        } catch (RuntimeException ignored) {
            // Marker accessors may throw on partial or restored pairs; omit request markers.
        }
        try {
            List<Marker> responseMarkers = pair == null ? List.of() : pair.responseMarkers();
            if (responseDoc != null && responseMarkers != null && !responseMarkers.isEmpty()) {
                putBodyMarkers(responseDoc, RequestResponseDocBuilder.convertTrafficMarkersToList(responseMarkers));
            }
        } catch (RuntimeException ignored) {
            // Marker accessors may throw on partial or restored pairs; omit response markers.
        }
    }

    private static void putBodyMarkers(Map<String, Object> doc, List<Map<String, Object>> markers) {
        if (doc == null) {
            return;
        }
        Map<String, Object> body = StringKeyedMaps.copy((Map<?, ?>) doc.get("body"));
        body.put("markers", markers);
        doc.put("body", body);
    }

}
