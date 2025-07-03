package ai.attackframework.vectors.sources.burp.utils.opensearch;

import ai.attackframework.vectors.sources.burp.utils.Logger;
import org.opensearch.client.opensearch.core.InfoResponse;

public class OpenSearchClientWrapper {

    public static OpenSearchStatus testConnection(String baseUrl) {
        try {
            org.opensearch.client.opensearch.OpenSearchClient client = OpenSearchConnector.getClient(baseUrl);
            InfoResponse info = client.info();

            String version = info.version().number();
            String distribution = info.version().distribution();

            return new OpenSearchStatus(true, distribution, version, "Connection successful");

        } catch (Exception e) {
            String msg = "OpenSearch connection test failed: " + e.getMessage();
            Logger.logError(msg);
            return new OpenSearchStatus(false, "", "", msg);
        }
    }

    public static OpenSearchStatus safeTestConnection(String baseUrl) {
        try {
            return testConnection(baseUrl);
        } catch (Exception e) {
            String msg = "OpenSearch connection test failed: " + e.getMessage();
            Logger.logError(msg);
            return new OpenSearchStatus(false, "", "", msg);
        }
    }

    private static String extractJsonValue(String json, String key) {
        int idx = json.indexOf(key);
        if (idx == -1) return "";

        int colon = json.indexOf(":", idx);
        if (colon == -1) return "";

        int quoteStart = json.indexOf("\"", colon);
        if (quoteStart == -1) return "";

        quoteStart += 1;

        int quoteEnd = json.indexOf("\"", quoteStart);
        if (quoteEnd == -1) return "";

        return json.substring(quoteStart, quoteEnd);
    }

    public record OpenSearchStatus(boolean success, String distribution, String version, String message) {}
}
