package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.LazySchedulers;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Ensures {@link SitemapIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Sitemap not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class SitemapIndexReporterTest {

    @AfterEach
    public void resetState() {
        SitemapIndexReporter.stop();
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void start_defersSchedulerUntilStartupSnapshotCompletes() {
        RuntimeConfig.setExportRunning(true);

        SitemapIndexReporter.start();

        assertThat(LazySchedulers.peek(SitemapIndexReporter.class, "SCHEDULER")).isNull();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        SitemapIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        SitemapIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenSitemapNotInDataSources() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
        SitemapIndexReporter.pushSnapshotNow();
    }

    @Test
    void pushNewItemsOnly_completesWithoutThrow_whenApiNull() {
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(null);
        SitemapIndexReporter.pushNewItemsOnly();
    }

    @Test
    void pushNewItemsOnly_completesWithoutThrow_whenExportNotRunning() {
        RuntimeConfig.setExportRunning(false);
        SitemapIndexReporter.pushNewItemsOnly();
    }

    @Test
    void buildSitemapDoc_survivesMalformedRequest_andReconstructsUrl() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenThrow(new IllegalStateException("URL is invalid."));
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/login");
        when(request.pathWithoutQuery()).thenReturn("/login");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("auth.example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        HttpRequestResponse item = mock(HttpRequestResponse.class);
        when(item.request()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        when(item.hasResponse()).thenReturn(false);

        Map<String, Object> doc = SitemapIndexReporter.buildSitemapDoc(item);

        assertThat(doc).isNotNull();
        assertThat(doc.keySet()).contains("burp", "request", "response", "meta");
        assertThat(doc.keySet())
                .doesNotContain("request_id", "source", "url", "method", "path", "host", "status", "param_names");
        Map<?, ?> requestDoc = nestedMap(doc, "request");
        Map<?, ?> urlDoc = nestedMap(requestDoc, "url");
        assertThat(urlDoc.get("raw")).isEqualTo("https://auth.example.com/login");
        assertThat(urlDoc.get("scheme")).isEqualTo("https");
        assertThat(urlDoc.get("host")).isEqualTo("auth.example.com");
        assertThat(urlDoc.get("port")).isEqualTo(443);
        assertThat(requestDoc.get("method")).isEqualTo("GET");
        assertThat(requestDoc.containsKey("port")).isFalse();
        Map<?, ?> pathDoc = nestedMap(requestDoc, "path");
        assertThat(pathDoc.get("with_query")).isEqualTo("/login");
        Map<?, ?> protocol = nestedMap(requestDoc, "protocol");
        assertThat(protocol.containsKey("scheme")).isFalse();
        assertThat(protocol.get("http_version")).isEqualTo("HTTP/1.1");
    }

    @Test
    void buildSitemapDoc_parametersOnlyContainUrlParams_notBodyEnumeration() {
        // Production code uses request.parameters(HttpParameterType.URL) so binary bodies
        // mislabeled as form-urlencoded cannot inflate request.parameters with synthetic BODY entries.
        // We prove that here by stubbing two distinct lists for parameters() and parameters(URL):
        // the doc's request.parameters must reflect only the typed URL list.
        ParsedHttpParameter urlParam = mock(ParsedHttpParameter.class);
        when(urlParam.name()).thenReturn("user");
        ParsedHttpParameter bodyParam = mock(ParsedHttpParameter.class);
        when(bodyParam.name()).thenReturn("synthetic_body_only");
        List<ParsedHttpParameter> urlOnly = List.of(urlParam);
        List<ParsedHttpParameter> allIncludingBody = List.of(urlParam, bodyParam);

        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://api.example.com/login?user=alice");
        when(request.method()).thenReturn("POST");
        when(request.path()).thenReturn("/login");
        when(request.pathWithoutQuery()).thenReturn("/login");
        when(request.query()).thenReturn("user=alice");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(allIncludingBody);
        when(request.parameters(HttpParameterType.URL)).thenReturn(urlOnly);
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("api.example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        HttpRequestResponse item = mock(HttpRequestResponse.class);
        when(item.request()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        when(item.hasResponse()).thenReturn(false);

        Map<String, Object> doc = SitemapIndexReporter.buildSitemapDoc(item);

        assertThat(doc).isNotNull();
        Map<?, ?> requestDoc = nestedMap(doc, "request");
        Object parametersObject = requestDoc.get("parameters");
        assertThat(parametersObject)
                .as("sitemap request.parameters must be drawn from the URL accessor, not the all-types accessor")
                .isInstanceOf(List.class);
        List<?> parameters = (List<?>) parametersObject;
        assertThat(parameters).hasSize(1);
        Map<?, ?> parameter = (Map<?, ?>) parameters.get(0);
        assertThat(parameter.get("name")).isEqualTo("user");
        assertThat(doc.containsKey("param_names")).isFalse();
        verify(request, never()).parameters();
    }

    @Test
    void buildSitemapDoc_overlaysPairLevelRequestMarkersIntoRequestBody() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://api.example.com/login");
        when(request.method()).thenReturn("POST");
        when(request.path()).thenReturn("/login");
        when(request.pathWithoutQuery()).thenReturn("/login");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters(HttpParameterType.URL)).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        Range range = mock(Range.class);
        when(range.startIndexInclusive()).thenReturn(10);
        when(range.endIndexExclusive()).thenReturn(20);
        Marker marker = mock(Marker.class);
        when(marker.range()).thenReturn(range);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("api.example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        HttpRequestResponse item = mock(HttpRequestResponse.class);
        when(item.request()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        when(item.hasResponse()).thenReturn(false);
        when(item.requestMarkers()).thenReturn(List.of(marker));
        when(item.responseMarkers()).thenReturn(List.of());

        Map<String, Object> doc = SitemapIndexReporter.buildSitemapDoc(item);
        Map<?, ?> requestDoc = nestedMap(doc, "request");
        Map<?, ?> body = nestedMap(requestDoc, "body");
        List<?> markers = (List<?>) body.get("markers");

        assertThat(markers).hasSize(1);
        Map<?, ?> firstMarker = (Map<?, ?>) markers.get(0);
        assertThat(firstMarker.get("start_inclusive")).isEqualTo(10);
        assertThat(firstMarker.get("end_exclusive")).isEqualTo(20);
    }

    @Test
    void pushNewItemsOnly_completesWithoutThrow_whenSitemapNotInDataSources() {
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
        SitemapIndexReporter.pushNewItemsOnly();
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        Object value = parent.get(key);
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }
}
