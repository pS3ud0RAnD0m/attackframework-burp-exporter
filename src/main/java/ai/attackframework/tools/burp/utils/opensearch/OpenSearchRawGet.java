package ai.attackframework.tools.burp.utils.opensearch;

import java.net.URI;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;

/**
 * Performs a raw HTTP GET to the OpenSearch root (/) with the same auth, SSL, and
 * HTTP version policy (NEGOTIATE) as {@link OpenSearchConnector}, so we can log the
 * actual protocol and status line from the wire (including HTTP/2 when negotiated).
 */
public final class OpenSearchRawGet {

    private OpenSearchRawGet() {}

    /**
     * Result of a raw GET / request: status line details, body, and log strings (real request/response with redaction).
     * When the request fails before receiving a response, {@code protocol} is null and {@code statusCode} is 0.
     */
    public record RawGetResult(
            int statusCode, String protocol, String reasonPhrase, String body,
            String requestForLog, java.util.List<String> responseHeaderLines) {}

    /**
     * Performs GET / against baseUrl with the same credentials and insecure-SSL behavior as the connector.
     * Uses the async client with {@code HttpVersionPolicy.NEGOTIATE} so HTTP/2 is used when supported.
     * Returns the actual HTTP version, status code, reason phrase, and response body from the wire.
     */
    public static RawGetResult performRawGet(String baseUrl, String username, String password) {
        String normalized = baseUrl == null ? "" : baseUrl.replaceFirst("^\\s+", "").trim().replaceAll("/+$", "");
        boolean credsUsed = username != null && !username.isBlank() && password != null && !password.isBlank();
        if (normalized.isEmpty()) {
            String reqLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", "/", null, credsUsed);
            return new RawGetResult(0, null, "Invalid base URL", "", reqLog, java.util.List.of());
        }
        String requestUri = normalized + "/";
        boolean insecure = OpenSearchConnector.isInsecureEnabled();
        try {
            URI uri = URI.create(requestUri);
            HttpHost host = new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            try (CloseableHttpAsyncClient client = buildAsyncClient(host, username, password, insecure)) {
                client.start();
                SimpleHttpRequest request = SimpleRequestBuilder.get(requestUri).build();
                Future<SimpleHttpResponse> future = client.execute(request, null);
                SimpleHttpResponse response = future.get();
                String protocol = response.getVersion() != null ? response.getVersion().toString() : null;
                int code = response.getCode();
                String reason = response.getReasonPhrase();
                String body = response.getBodyText() != null ? response.getBodyText() : "";
                String reqForLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, protocol, credsUsed);
                java.util.List<String> respHeaderLines = new java.util.ArrayList<>();
                for (Header h : response.getHeaders()) {
                    String name = h.getName();
                    String value = OpenSearchLogFormat.shouldRedactHeader(name) ? "***" : (h.getValue() != null ? h.getValue() : "");
                    respHeaderLines.add(name + ": " + value);
                }
                return new RawGetResult(code, protocol, reason, body, reqForLog, respHeaderLines);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            String protocol = OpenSearchLogFormat.parseProtocolFromException(e);
            String reqForLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, protocol, credsUsed);
            return new RawGetResult(0, null, msg, "", reqForLog, java.util.List.of());
        } catch (java.security.GeneralSecurityException | java.io.IOException
                | java.util.concurrent.ExecutionException | IllegalArgumentException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            String protocol = OpenSearchLogFormat.parseProtocolFromException(e);
            String reqForLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, protocol, credsUsed);
            return new RawGetResult(0, null, msg, "", reqForLog, java.util.List.of());
        }
    }

    private static final Timeout RESPONSE_TIMEOUT = Timeout.ofSeconds(5);

    private static CloseableHttpAsyncClient buildAsyncClient(HttpHost host, String username, String password, boolean insecure)
            throws java.security.GeneralSecurityException {
        var clientBuilder = HttpAsyncClients.custom();
        PoolingAsyncClientConnectionManagerBuilder connManagerBuilder =
                PoolingAsyncClientConnectionManagerBuilder.create()
                        .setDefaultTlsConfig(TlsConfig.custom()
                                .setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
                                .build());
        clientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setResponseTimeout(RESPONSE_TIMEOUT)
                .build());
        if (username != null && !username.isBlank() && password != null && !password.isBlank()) {
            BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(
                    new AuthScope(host),
                    new UsernamePasswordCredentials(username, password.toCharArray()));
            clientBuilder.setDefaultCredentialsProvider(credsProvider);
        }
        if (insecure && "https".equalsIgnoreCase(host.getSchemeName())) {
            SSLContext sslContext = SSLContextBuilder.create()
                    .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                    .build();
            connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .buildAsync());
        }
        AsyncClientConnectionManager connManager = connManagerBuilder.build();
        clientBuilder.setConnectionManager(connManager);
        return clientBuilder.build();
    }
}
