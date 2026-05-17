package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.Logger;

/**
 * Locks down the shape of the Repeater Tabs startup completion summary emitted by
 * {@code RepeaterTabsIndexReporter.logStartupExportCompletionSummary()}.
 *
 * <p>Uses reflection to invoke the package-private lifecycle hooks and the private summary
 * method so the test can assert prefix + {@link SnapshotSummary} body + metadata suffix
 * composition without spinning up Burp's Montoya API.</p>
 *
 * <p>Static state is reset per-test in the constructor (JUnit 5 creates a new instance per
 * {@code @Test} method by default); the log listener is registered/unregistered around each
 * test body via try/finally so no lifecycle-hook methods are needed.</p>
 */
class RepeaterTabsStartupSummaryTest {

    private final List<String> capturedMessages = new ArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level) && message.startsWith("[Traffic] Repeater Tabs startup export complete")) {
            capturedMessages.add(message);
        }
    };

    public RepeaterTabsStartupSummaryTest() {
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        RepeaterTabsIndexReporter.clearSessionState();
    }

    @Test
    void logStartupExportCompletionSummary_composesPrefixBodyAndMetadataSuffix() throws Exception {
        Logger.registerListener(listener);
        try {
            invokeStatic("openCaptureWindowForCurrentRun");

            ExportStats.recordTrafficToolTypeSuccess("REPEATER_TABS", 2);
            FileExportStats.recordTrafficToolTypeSuccess("REPEATER_TABS", 2);

            invokeStatic("logStartupExportCompletionSummary");
            drainEventDispatchThread();

            assertThat(capturedMessages).hasSize(1);
            String line = capturedMessages.get(0);
            assertThat(line).startsWith("[Traffic] Repeater Tabs startup export complete startupSession=");
            assertThat(line).contains(" captured 0 tab(s)");
            assertThat(line).contains("file={success=2, failure=0}");
            assertThat(line).contains("openSearch={success=2, failure=0}");
            assertThat(line).endsWith(".");
        } finally {
            Logger.unregisterListener(listener);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void logStartupExportCompletionSummary_rendersZeroedBodyWhenBaselineAbsent() throws Exception {
        Logger.registerListener(listener);
        try {
            invokeStatic("logStartupExportCompletionSummary");
            drainEventDispatchThread();

            assertThat(capturedMessages).hasSize(1);
            String line = capturedMessages.get(0);
            assertThat(line).contains(" captured 0 tab(s); ");
            assertThat(line).contains("file={success=0, failure=0}");
            assertThat(line).contains("openSearch={success=0, failure=0}");
        } finally {
            Logger.unregisterListener(listener);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    private static void invokeStatic(String methodName) throws Exception {
        Method method = RepeaterTabsIndexReporter.class.getDeclaredMethod(methodName);
        method.setAccessible(true);
        method.invoke(null);
    }

    private static void drainEventDispatchThread() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }
}
