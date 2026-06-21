package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.EnumMap;
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
import burp.api.montoya.http.message.requests.HttpRequest;

/** Unit tests for {@link CompressedWireBodyParamsLog}. */
class CompressedWireBodyParamsLogTest {

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
        CompressedWireBodyParamsLog.startForCurrentRun();
    }

    @AfterEach
    void tearDown() {
        CompressedWireBodyParamsLog.clearRunState();
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void record_replaced_flushesStartupInfoAndDebugSamples() throws Exception {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/form");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/form");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
        CompressedWireBodyParamsLog.flushStartupSummary();
        flushLogListeners();

        assertThat(infoMessages).hasSize(1);
        assertThat(infoMessages.get(0))
                .contains("[ParameterIntegrity]")
                .contains("replaced=1")
                .contains("startup/backlog");
        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0)).contains("REPLACED").contains("https://example.test/form");
    }

    @Test
    void record_liveReplaced_emitsWarnOncePerUrl() throws Exception {
        RuntimeConfig.setExportRunning(true);
        CompressedWireBodyParamsLog.flushStartupSummary();
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/live");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/live");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
        flushLogListeners();

        assertThat(warnMessages).hasSize(1);
        assertThat(warnMessages.get(0)).contains("compressed-wire BODY params replaced");
    }

    @Test
    void flushStopSummary_emitsPendingLiveCounts() throws Exception {
        RuntimeConfig.setExportRunning(true);
        CompressedWireBodyParamsLog.flushStartupSummary();
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/stop");
        Map<String, Object> requestDoc = Map.of("url", "https://example.test/stop");

        CompressedWireBodyParamsLog.record(
                request, null, requestDoc, CompressedWireBodyParamsLog.Category.SKIP_RESCUED);
        CompressedWireBodyParamsLog.flushStopSummary();
        flushLogListeners();

        assertThat(debugMessages).hasSize(1);
        assertThat(debugMessages.get(0))
                .contains("SKIP_RESCUED")
                .contains("https://example.test/stop");
        assertThat(infoMessages).isEmpty();
    }

    @Test
    void formatInfoSummaryForTests_listsAllCategories() {
        Map<CompressedWireBodyParamsLog.Category, Integer> counts = new EnumMap<>(CompressedWireBodyParamsLog.Category.class);
        counts.put(CompressedWireBodyParamsLog.Category.REPLACED, 2);
        counts.put(CompressedWireBodyParamsLog.Category.WIRE_DROPPED, 1);
        counts.put(CompressedWireBodyParamsLog.Category.SUPPLEMENTAL_ADDED, 3);
        counts.put(CompressedWireBodyParamsLog.Category.SKIP_RESCUED, 4);

        String line = CompressedWireBodyParamsLog.formatInfoSummaryForTests("test", counts);

        assertThat(line)
                .contains("replaced=2")
                .contains("wire_dropped=1")
                .contains("supplemental_added=3")
                .contains("skip_rescued=4")
                .contains("during test");
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }
}
