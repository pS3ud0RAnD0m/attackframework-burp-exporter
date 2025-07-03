package ai.attackframework.vectors.sources.burp.utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;

public class OpenSearchClient {

    public static OpenSearchStatus testConnection(String baseUrl) {
        try {
            URI uri = URI.create(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
            HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);

            int status = connection.getResponseCode();
            if (status != 200) {
                return new OpenSearchStatus(false, "", "", "HTTP " + status);
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            for (String line; (line = reader.readLine()) != null; ) {
                response.append(line);
            }
            reader.close();

            String body = response.toString();
            String distribution = extractJsonValue(body, "\"distribution\"");
            String version = extractJsonValue(body, "\"number\"");
            boolean looksLikeOpenSearch = body.toLowerCase().contains("opensearch");

            if (!looksLikeOpenSearch) {
                return new OpenSearchStatus(false, "", "", "Unexpected response");
            }

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
