package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Traffic-index {@code request.path} sub-document.
 */
final class TrafficRequestPathFields {

    private TrafficRequestPathFields() {}

    static Map<String, Object> from(
            String pathWithQuery, String pathWithoutQuery, String query, String fileExtension) {
        Map<String, Object> path = new LinkedHashMap<>();
        path.put("with_query", pathWithQuery);
        path.put("without_query", nullToEmpty(pathWithoutQuery));
        path.put("query", nullToEmpty(query));
        path.put("file_extension", nullToEmpty(fileExtension));
        return path;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
