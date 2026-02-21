package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import javax.swing.SwingUtilities;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class LoggerPipelineIT {

    private final List<Event> events = new CopyOnWriteArrayList<>();
    private final CountDownLatch latch = new CountDownLatch(1);
    private final Logger.LogListener listener = (level, message) -> {
        events.add(new Event(level, message));
        latch.countDown();
    };

    @AfterEach
    void tearDown() {
        // Best-effort cleanup if future tests register their own listeners.
        Logger.unregisterListener(listener);
        events.clear();
        while (latch.getCount() > 0) {
            latch.countDown();
        }
    }

    @Test
    void internalLogger_debug_emitsOnce_toListenerBus() throws Exception {
        Logger.registerListener(listener);

        String msg = "pipeline: internal debug";
        SwingUtilities.invokeAndWait(() -> Logger.logDebug(msg));

        await();
        long count = events.stream()
                .filter(e -> e.message().equals(msg) && e.level().equalsIgnoreCase("DEBUG"))
                .count();

        // UiAppender ignores our internal logger; the bus should see exactly one event.
        assertThat(count).isEqualTo(1);
    }

    @Test
    void internalLogger_error_withThrowable_includesExceptionSummary() throws Exception {
        Logger.registerListener(listener);

        String msg = "pipeline: internal error";
        SwingUtilities.invokeAndWait(() -> Logger.logError(msg, new IllegalStateException("boom")));

        await();
        assertThat(events)
                .anySatisfy(e -> {
                    assertThat(e.level()).isEqualToIgnoringCase("ERROR");
                    assertThat(e.message()).contains("pipeline: internal error");
                    assertThat(e.message()).contains("IllegalStateException").contains("boom");
                });
    }

    @Test
    void externalSlf4j_logger_routesThroughUiAppender_toListenerBus() throws Exception {
        Logger.registerListener(listener);

        org.slf4j.Logger thirdParty = LoggerFactory.getLogger("third.party.demo");
        String msg = "pipeline: external info";
        SwingUtilities.invokeAndWait(() -> thirdParty.info(msg));

        await();
        assertThat(events)
                .anySatisfy(e -> {
                    assertThat(e.level()).isEqualToIgnoringCase("INFO");
                    assertThat(e.message()).contains(msg);
                });
    }

    private void await() throws InterruptedException {
        // generous allowance; Logback + EDT (if any) are fast in headless tests
        boolean ok = latch.await(2, TimeUnit.SECONDS);
        assertThat(ok).as("Timed out waiting for log event").isTrue();
    }

    private record Event(String level, String message) {
        Event {
            level = Objects.toString(level, "");
            message = Objects.toString(message, "");
        }
    }
}
