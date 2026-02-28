package ai.attackframework.tools.burp.utils.opensearch;

import java.net.URI;

/**
 * Shared formatting for OpenSearch HTTP request/response logging (Create Index, Test Connection).
 * Produces one log entry per request and per response, with indented raw content.
 */
public final class OpenSearchLogFormat {

    private OpenSearchLogFormat() {}

    /** Builds a log-friendly raw HTTP request string (request line, Host, optional Content-Type and body). */
    public static String buildRawRequest(String baseUrl, String method, String path, String body) {
        try {
            URI uri = URI.create(baseUrl.replaceFirst("^\\s+", "").trim());
            String host = uri.getHost() != null ? uri.getHost() : "";
            if (uri.getPort() > 0 && uri.getPort() != (uri.getScheme() != null && "https".equals(uri.getScheme()) ? 443 : 80)) {
                host = host + ":" + uri.getPort();
            }
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(" ").append(path).append(" HTTP/1.1\nHost: ").append(host);
            if (body != null && !body.isEmpty()) {
                sb.append("\nContent-Type: application/json\n\n").append(body);
            }
            return sb.toString();
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(" ").append(path).append(" HTTP/1.1");
            if (body != null && !body.isEmpty()) {
                sb.append("\nContent-Type: application/json\n\n").append(body);
            }
            return sb.toString();
        }
    }

    /** Builds a log-friendly raw HTTP response string (status line, headers, body). */
    public static String buildRawResponse(String body) {
        return "HTTP/1.1 200 OK\nContent-Type: application/json\n\n" + (body != null ? body : "");
    }

    /** Prefixes each line so raw request/response aligns with wrapped-line indent in the log. */
    public static String indentRaw(String raw) {
        if (raw == null || raw.isEmpty()) return raw;
        return "  " + raw.replace("\n", "\n  ");
    }
}
