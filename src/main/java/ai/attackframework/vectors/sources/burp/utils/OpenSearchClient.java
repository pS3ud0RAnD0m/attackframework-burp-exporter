package ai.attackframework.vectors.sources.burp.utils;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class OpenSearchClient {

    public static OpenSearchStatus testConnection(String baseUrl) {
        try {
            URL url = new URL(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);

            int status = connection.getResponseCode();
            if (status != 200) {
                return new OpenSearchStatus(false, "", "", "HTTP " + status);
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            for (String line; (line = reader.readLine()) != null;) {
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

    private static String extractJsonValue(String json, String key) {
        int idx = json.indexOf(key);
        if (idx == -1) return "";
        int start = json.indexOf(":", idx) + 1;
        int quoteStart = json.indexOf("\"", start) + 1;
        int quoteEnd = json.indexOf("\"", quoteStart);
        if (start == -1 || quoteStart == -1 || quoteEnd == -1) return "";
        return json.substring(quoteStart, quoteEnd);
    }

    public record OpenSearchStatus(boolean success, String distribution, String version, String message) {}
}
