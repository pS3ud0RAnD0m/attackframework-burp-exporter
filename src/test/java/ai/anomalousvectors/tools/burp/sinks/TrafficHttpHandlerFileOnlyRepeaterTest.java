package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

class TrafficHttpHandlerFileOnlyRepeaterTest {

    @Test
    void liveRepeaterTraffic_flushesToFiles_whenOnlyFileSinkIsEnabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("traffic-handler-file-only-repeater");
            RuntimeConfig.updateState(fileOnlyTrafficState(root));
            RuntimeConfig.setExportRunning(true);
            FileExportService.createSelectedExportFiles(List.of(ConfigKeys.SRC_TRAFFIC));

            TrafficHttpHandler handler = new TrafficHttpHandler();
            HttpRequestToBeSent request = requestToBeSent(
                    "GET /repeater/live HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    77,
                    ToolType.REPEATER);
            HttpResponseReceived response = responseReceived(
                    request,
                    77,
                    ToolType.REPEATER,
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse exchange = mock(HttpRequestResponse.class);
            when(exchange.request()).thenReturn(request);
            when(exchange.response()).thenReturn(response);
            RepeaterLiveMetadataTracker.observe(
                    exchange,
                    new RepeaterMetadataFields.Metadata("Manual Tab", "Manual Group"),
                    System.currentTimeMillis());

            RepeaterMetadataFields.Metadata requestStageMetadata =
                    TrafficHttpHandler.resolveRequestStageRepeaterMetadata(request, ToolType.REPEATER);
            RepeaterMetadataFields.Metadata responseStageMetadata =
                    TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                            request,
                            response,
                            ToolType.REPEATER,
                            requestStageMetadata);
            Map<String, Object> document = handler.buildDocument(
                    response,
                    request,
                    true,
                    1L,
                    2L,
                    ToolType.REPEATER,
                    responseStageMetadata);
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(
                    TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, document);
            FileExportService.emit(prepared);

            Path jsonlPath = root.resolve(RuntimeConfig.indexNameForKey("traffic") + ".jsonl");
            assertThat(jsonlPath).exists();
            String contents = Files.readString(jsonlPath);
            assertThat(contents).contains("\"burp\":");
            assertThat(contents).contains("\"reporting_tool\":\"Repeater\"");
            assertThat(contents).doesNotContain("\"tool_type\"");
            assertThat(contents).contains("\"tab_name\":\"Manual Tab\"");
            assertThat(contents).contains("\"tab_group\":\"Manual Group\"");
            assertThat(contents).contains("\"repeater\":");
            assertThat(contents).doesNotContain("OpenSearchTrafficHandler");
        } finally {
            FileExportService.resetForTests();
            ExportReporterLifecycle.resetForTests();
        }
    }

    private static ConfigState.State fileOnlyTrafficState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }

    private static HttpRequestToBeSent requestToBeSent(String rawRequest, int messageId, ToolType toolType) {
        HttpRequestToBeSent request = mock(HttpRequestToBeSent.class);
        HttpService service = mock(HttpService.class);
        ToolSource toolSource = mock(ToolSource.class);
        ByteArray requestBytes = byteArray(rawRequest);

        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(toolSource.toolType()).thenReturn(toolType);

        when(request.toolSource()).thenReturn(toolSource);
        when(request.messageId()).thenReturn(messageId);
        when(request.isInScope()).thenReturn(true);
        when(request.url()).thenReturn("https://example.test/repeater/live");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/repeater/live");
        when(request.pathWithoutQuery()).thenReturn("/repeater/live");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.annotations()).thenReturn(null);
        when(request.contentType()).thenReturn(ContentType.NONE);
        when(request.toByteArray()).thenReturn(requestBytes);
        return request;
    }

    private static HttpResponseReceived responseReceived(
            HttpRequestToBeSent request,
            int messageId,
            ToolType toolType,
            String rawResponse) {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        ToolSource toolSource = mock(ToolSource.class);
        ByteArray responseBytes = byteArray(rawResponse);

        when(toolSource.toolType()).thenReturn(toolType);
        when(response.initiatingRequest()).thenReturn(request);
        when(response.messageId()).thenReturn(messageId);
        when(response.toolSource()).thenReturn(toolSource);
        when(response.annotations()).thenReturn(null);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(MimeType.HTML);
        when(response.statedMimeType()).thenReturn(MimeType.HTML);
        when(response.inferredMimeType()).thenReturn(MimeType.HTML);
        when(response.body()).thenReturn(null);
        when(response.bodyOffset()).thenReturn(0);
        when(response.bodyToString()).thenReturn("A");
        when(response.markers()).thenReturn(List.of());
        when(response.attributes(any(AttributeType[].class))).thenReturn(List.of());
        when(response.toByteArray()).thenReturn(responseBytes);
        return response;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

}
