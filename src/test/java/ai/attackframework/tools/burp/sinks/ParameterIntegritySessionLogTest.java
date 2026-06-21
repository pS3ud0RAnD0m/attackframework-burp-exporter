package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;

/** Unit tests for {@link ParameterIntegritySessionLog}. */
class ParameterIntegritySessionLogTest {

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
    }

    @AfterEach
    void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
    }

    @Test
    void flushStopDebugValidation_doesNotEmitInfoOrOpenSearchProbeHints() throws Exception {
        ParameterIntegritySessionLog.flushStopDebugValidation();
        flushLogListeners();

        assertThat(infoMessages).isEmpty();
        assertThat(debugMessages).noneMatch(m -> m.contains("OpenSearch reconcile"));
        assertThat(debugMessages).noneMatch(m -> m.contains("acceptance probe"));
    }

    @Test
    void logFinalExporterStatsPush_successIsInfoOnly() throws Exception {
        ParameterIntegritySessionLog.logFinalExporterStatsPush(ExporterStatsPushOutcome.success());
        flushLogListeners();

        assertThat(infoMessages).anyMatch(m -> m.equals("[ParameterIntegrity] Final exporter stats push: success."));
        assertThat(debugMessages).isEmpty();
    }

    @Test
    void logFinalExporterStatsPush_failureIsWarnOnly() throws Exception {
        ParameterIntegritySessionLog.logFinalExporterStatsPush(
                ExporterStatsPushOutcome.failed("connection closed"));
        flushLogListeners();

        assertThat(warnMessages).anyMatch(m -> m.contains("failed (connection closed)"));
        assertThat(debugMessages).isEmpty();
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }
}
