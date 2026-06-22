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
import burp.api.montoya.http.message.requests.HttpRequest;

/** Unit tests for {@link BodyParameterTruncationLog}. */
class BodyParameterTruncationLogTest {

    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final List<String> debugMessages = new CopyOnWriteArrayList<>();
    private final List<String> warnMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level)) {
            infoMessages.add(message);
        } else if ("DEBUG".equals(level)) {
            debugMessages.add(message);
        } else if ("WARN".equals(level)) {
            warnMessages.add(message);
        }
    };

    @BeforeEach
    void setUp() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
        BodyParameterTruncationLog.startForCurrentRun();
    }

    @AfterEach
    void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        BodyParameterTruncationLog.clearRunState();
    }

    @Test
    void flushStartupSummary_dedupesByRequestUrl() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/form");
        Map<String, Object> requestDoc = Map.of();

        BodyParameterTruncationLog.record(request, null, requestDoc, 5);
        BodyParameterTruncationLog.record(request, null, requestDoc, 7);
        BodyParameterTruncationLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("BODY parameters truncated")
                .contains("1 unique request.url")
                .contains("dropped_body_params=12")
                .contains("No raw request data was lost")
                .contains("Data-Integrity#body_params_truncated")
                .doesNotContain("Wiki -> Data Integrity -> Logging")
                .doesNotContain("Drill-down if affected endpoints matter")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=body_params_truncated")
                .doesNotContain("urls=");
        assertThat(warnMessages).isEmpty();
        assertThat(ExportStats.getDocsBodyParamsTruncated()).isEqualTo(2);
        assertThat(ExportStats.getBodyParamsDroppedTotal()).isEqualTo(12);
    }

    @Test
    void afterStartupFlush_liveTruncationsDebugImmediately() throws Exception {
        HttpRequest first = mock(HttpRequest.class);
        when(first.url()).thenReturn("https://example.test/live-a");
        HttpRequest second = mock(HttpRequest.class);
        when(second.url()).thenReturn("https://example.test/live-b");
        Map<String, Object> requestDoc = Map.of();

        BodyParameterTruncationLog.flushStartupSummary();
        BodyParameterTruncationLog.record(first, null, requestDoc, 2);
        BodyParameterTruncationLog.record(second, null, requestDoc, 3);
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(warnMessages).isEmpty();
        assertThat(debugMessages).hasSize(2);
        assertThat(debugMessages.get(0))
                .contains("[ParameterIntegrity]")
                .contains("No raw request data was lost")
                .contains("Data-Integrity#body_params_truncated")
                .doesNotContain("category=body_params_truncated")
                .doesNotContain("live-a")
                .doesNotContain("...");
        assertThat(debugMessages.get(1))
                .contains("BODY parameters truncated")
                .doesNotContain("category=body_params_truncated")
                .doesNotContain("live-b")
                .doesNotContain("...");
    }

    @Test
    void formatStartupSummaryForTests_listsSampleUrls() {
        Map<String, Integer> totals = new LinkedHashMap<>();
        totals.put("https://example.test/a", 4);
        totals.put("https://example.test/b", 6);

        String line = BodyParameterTruncationLog.formatStartupSummaryForTests(totals);

        assertThat(line)
                .contains("2 unique request.url")
                .contains("dropped_body_params=10")
                .contains("Data-Integrity#body_params_truncated")
                .doesNotContain("event.type=parameter_integrity_detail")
                .doesNotContain("category=body_params_truncated")
                .doesNotContain("https://example.test/a")
                .doesNotContain("https://example.test/b");
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }
}
