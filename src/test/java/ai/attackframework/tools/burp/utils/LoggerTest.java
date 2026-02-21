package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LoggerTest {

    @Test
    void registerListener_receivesInfoAndErrorLogs() throws Exception {
        List<String> seen = new ArrayList<>();
        Logger.LogListener listener = (level, msg) -> seen.add(level + ":" + msg);

        Logger.registerListener(listener);

        // Run logging on EDT so listener is invoked synchronously (Logger dispatches to EDT when off it)
        SwingUtilities.invokeAndWait(() -> {
            Logger.logInfo("hello");
            Logger.logError("world");
        });

        assertThat(seen).hasSize(2);
        assertThat(seen.get(0)).startsWith("INFO:").contains("hello");
        assertThat(seen.get(1)).startsWith("ERROR:").contains("world");
    }

    /**
     * ReplayableLogListener receives buffered messages when registered (e.g. LogPanel after tab switch).
     * Plain LogListener does not receive replay, so tests and other listeners are not spammed.
     */
    @Test
    void replayableListener_receivesReplay_plainListener_doesNot() throws Exception {
        // Put a message in the buffer
        SwingUtilities.invokeAndWait(() -> Logger.logInfo("replay-this"));

        List<String> replaySeen = new ArrayList<>();
        Logger.ReplayableLogListener replayable = (level, msg) -> replaySeen.add(level + ":" + msg);
        Logger.registerListener(replayable);
        SwingUtilities.invokeAndWait(() -> { /* drain EDT so replay runnable runs */ });

        assertThat(replaySeen).anyMatch(s -> s.contains("replay-this"));
        Logger.unregisterListener(replayable);

        // Plain listener: register after buffer has content; should not receive replay
        List<String> plainSeen = new ArrayList<>();
        Logger.LogListener plain = (level, msg) -> plainSeen.add(level + ":" + msg);
        Logger.registerListener(plain);
        SwingUtilities.invokeAndWait(() -> {});
        assertThat(plainSeen).isEmpty();
        SwingUtilities.invokeAndWait(() -> Logger.logInfo("direct-only"));
        assertThat(plainSeen).hasSize(1).allMatch(s -> s.contains("direct-only"));
        Logger.unregisterListener(plain);
    }

    @Test
    void replayBuffer_isBounded_andPreservesOrder() throws Exception {
        int cap = replayBufferSize();
        String prefix = "cap-test-";

        // Overwrite any previous buffer contents with our messages only.
        SwingUtilities.invokeAndWait(() -> {
            for (int i = 0; i < cap * 2; i++) {
                Logger.logInfo(prefix + i);
            }
        });

        List<String> replaySeen = new ArrayList<>();
        Logger.ReplayableLogListener replayable = (level, msg) -> {
            if (msg != null && msg.startsWith(prefix)) {
                replaySeen.add(msg);
            }
        };

        Logger.registerListener(replayable);
        SwingUtilities.invokeAndWait(() -> { /* drain EDT for replay */ });

        assertThat(replaySeen).hasSize(cap);
        assertThat(replaySeen.get(0)).contains(prefix + cap);
        assertThat(replaySeen.get(replaySeen.size() - 1)).contains(prefix + (cap * 2 - 1));

        Logger.unregisterListener(replayable);
    }

    @Test
    void registerListener_isIdempotent_noDuplicateDelivery() throws Exception {
        List<String> seen = new ArrayList<>();
        Logger.LogListener listener = (level, msg) -> seen.add(level + ":" + msg);

        Logger.registerListener(listener);
        Logger.registerListener(listener); // should be ignored

        SwingUtilities.invokeAndWait(() -> Logger.logInfo("dedupe-check"));

        assertThat(seen).hasSize(1);
        assertThat(seen.get(0)).contains("dedupe-check");

        Logger.unregisterListener(listener);
    }

    @Test
    void replayableListener_reRegister_onlyReplaysNewMessages() throws Exception {
        String prefix = "replay-reg-";
        List<String> seen = new ArrayList<>();
        Logger.ReplayableLogListener listener = (level, msg) -> {
            if (msg != null && msg.startsWith(prefix)) {
                seen.add(msg);
            }
        };

        SwingUtilities.invokeAndWait(() -> Logger.logInfo(prefix + "one"));
        Logger.registerListener(listener);
        SwingUtilities.invokeAndWait(() -> { /* drain EDT for replay */ });

        int sizeAfterFirst = seen.size();
        assertThat(sizeAfterFirst).isGreaterThanOrEqualTo(1);

        Logger.unregisterListener(listener);
        Logger.registerListener(listener);
        SwingUtilities.invokeAndWait(() -> { /* drain EDT for replay */ });

        assertThat(seen).hasSize(sizeAfterFirst);

        SwingUtilities.invokeAndWait(() -> Logger.logInfo(prefix + "two"));
        assertThat(seen).anyMatch(s -> s.equals(prefix + "two"));

        Logger.unregisterListener(listener);
    }

    private static int replayBufferSize() {
        try {
            var f = Logger.class.getDeclaredField("REPLAY_BUFFER_SIZE");
            f.setAccessible(true);
            return (int) f.get(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
