package ai.attackframework.tools.burp.utils.opensearch;

import ai.attackframework.tools.burp.utils.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link OpenSearchClientWrapper#testConnection(String)} emits log events
 * to the {@link Logger} listener bus so {@code LogPanel} can display connection attempts.
 */
class OpenSearchClientWrapperLoggingTest {

    private final List<LoggerEvent> events = new CopyOnWriteArrayList<>();
    private final CountDownLatch latch = new CountDownLatch(1);
    private final Logger.LogListener listener = (level, message) -> {
        events.add(new LoggerEvent(level, message));
        latch.countDown();
    };

    @AfterEach
    void tearDown() {
        Logger.unregisterListener(listener);
        events.clear();
        while (latch.getCount() > 0) {
            latch.countDown();
        }
    }

    @Test
    void testConnection_withInvalidUrl_emitsLogEvent() throws Exception {
        Logger.registerListener(listener);

        // Run on EDT so Logger listener is invoked synchronously (Logger dispatches to EDT when off it).
        SwingUtilities.invokeAndWait(() ->
                OpenSearchClientWrapper.testConnection("http://127.0.0.1:1"));

        assertThat(events)
                .anySatisfy(e -> {
                    assertThat(e.level()).isNotEmpty();
                    assertThat(e.message()).contains("[OpenSearch] Testing connection to:");
                });
    }

    private record LoggerEvent(String level, String message) {
        LoggerEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
