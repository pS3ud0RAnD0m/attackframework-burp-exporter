package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Ensures {@link SitemapIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Sitemap not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class SitemapIndexReporterTest {

    @AfterEach
    void resetState() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
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

        Map<?, ?> doc = (Map<?, ?>) callStatic(SitemapIndexReporter.class, "buildSitemapDoc", item);

        assertThat(doc).isNotNull();
        assertThat(doc.get("url")).isEqualTo("https://auth.example.com/login");
        assertThat(doc.get("method")).isEqualTo("GET");
        assertThat(doc.get("path")).isEqualTo("/login");
        assertThat(doc.get("host")).isEqualTo("auth.example.com");
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
}
