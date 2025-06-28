package ai.attackframework.vectors.sources.burp.utils;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class OpenSearchClient {

    public static boolean testConnection(String baseUrl) {
        try {
            URL url = new URL(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);

            int status = connection.getResponseCode();
            if (status != 200) {
                return false;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            for (String line; (line = reader.readLine()) != null;) {
                response.append(line);
            }
            reader.close();

            String body = response.toString().toLowerCase();
            return body.contains("opensearch") || body.contains("lucene_version") || body.contains("tagline");

        } catch (Exception e) {
            Logger.logError("OpenSearch connection test failed: " + e.getMessage());
            return false;
        }
    }
}
