package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

/** Unit tests for {@link BodyEnumerationSkippedLog}. */
class BodyEnumerationSkippedLogTest {

    private final List<String> debugMessages = new CopyOnWriteArrayList<>();
    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final List<String> warnMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("DEBUG".equals(level)) {
            debugMessages.add(message);
        } else if ("INFO".equals(level)) {
            infoMessages.add(message);
        } else if ("WARN".equals(level)) {
            warnMessages.add(message);
        }
    };

    @BeforeEach
    void setUp() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
        BodyEnumerationSkippedLog.startForCurrentRun();
    }

    @AfterEach
    void tearDown() {
        BodyEnumerationSkippedLog.clearRunState();
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void evaluateAndRecord_misgateSuspect_flushesStartupInfoAndDebugSummaries() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/form");
        byte[] body = "a=1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        List<HttpHeader> headers = List.of();

        BodyEnumerationSkippedLog.evaluateAndRecord(
                request,
                null,
                Map.of(),
                ContentType.URL_ENCODED,
                headers,
                HttpMessageDocSupport.INFERRED_CT_BINARY,
                body,
                true);
        BodyEnumerationSkippedLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).hasSize(1);
        assertThat(infoMessages.get(0))
                .contains("[ParameterIntegrity]")
                .contains("BODY params omitted")
                .contains("Mis-gate Suspects");
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("Mis-gate detail")
                .contains("https://example.test/form");
        assertThat(ExportStats.getDocsBodyEnumerationMisgateSuspect()).isZero();
    }

    @Test
    void isMisgateSuspect_matchesEvaluateAndRecordCriteria() {
        byte[] body = "a=1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(BodyEnumerationSkippedLog.isMisgateSuspect(
                ContentType.URL_ENCODED,
                List.of(),
                HttpMessageDocSupport.INFERRED_CT_BINARY,
                body,
                true)).isTrue();
        assertThat(BodyEnumerationSkippedLog.isMisgateSuspect(
                ContentType.URL_ENCODED,
                List.of(),
                HttpMessageDocSupport.INFERRED_CT_TEXT,
                body,
                true)).isFalse();
    }

    @Test
    void evaluateAndRecord_declaredGrpc_doesNotRecord() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/rpc");
        byte[] body = new byte[] {0x00, 0x01, 0x02};
        List<HttpHeader> headers = List.of(header("Content-Type", "application/grpc"));

        BodyEnumerationSkippedLog.evaluateAndRecord(
                request,
                null,
                Map.of(),
                ContentType.UNKNOWN,
                headers,
                HttpMessageDocSupport.INFERRED_CT_BINARY,
                body,
                true);
        BodyEnumerationSkippedLog.flushStartupSummary();
        flushLogListeners();

        assertThat(debugMessages).isEmpty();
        assertThat(ExportStats.getDocsBodyEnumerationMisgateSuspect()).isZero();
    }

    @Test
    void flushPeriodicSummary_emitsPendingLiveSuspects() throws Exception {
        RuntimeConfig.setExportRunning(true);
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/live");
        byte[] body = "x=1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        BodyEnumerationSkippedLog.flushStartupSummary();
        BodyEnumerationSkippedLog.evaluateAndRecord(
                request,
                null,
                Map.of(),
                ContentType.URL_ENCODED,
                List.of(),
                HttpMessageDocSupport.INFERRED_CT_BINARY,
                body,
                true);
        BodyEnumerationSkippedLog.flushPeriodicSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0)).contains("during live");
        assertThat(infoMessages).hasSize(1);
        assertThat(infoMessages.get(0)).contains("during live");
    }

    @Test
    void flushStopSummary_emitsRemainingLiveSuspects() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/stop");
        byte[] body = "y=2".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        BodyEnumerationSkippedLog.flushStartupSummary();
        BodyEnumerationSkippedLog.evaluateAndRecord(
                request,
                null,
                Map.of(),
                ContentType.MULTIPART,
                List.of(),
                HttpMessageDocSupport.INFERRED_CT_BINARY,
                body,
                true);
        BodyEnumerationSkippedLog.flushStopSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0)).contains("during stop");
        assertThat(infoMessages).isEmpty();
    }

    @Test
    void formatMisgateSummaryForTests_listsSampleUrls() {
        Map<String, Integer> urls = new LinkedHashMap<>();
        urls.put("https://example.test/a", 1);
        urls.put("https://example.test/b", 1);

        String line = BodyEnumerationSkippedLog.formatMisgateSummaryForTests(2, urls, "test");

        assertThat(line)
                .contains("2 request(s)")
                .contains("during test")
                .contains("https://example.test/a")
                .contains("https://example.test/b")
                .doesNotContain("Narrow acceptance probe");
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }
}
