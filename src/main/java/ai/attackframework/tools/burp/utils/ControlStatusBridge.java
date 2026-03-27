package ai.attackframework.tools.burp.utils;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Bridges runtime events to the Config control-status area.
 *
 * <p>The exporter has background paths such as spill handling that may need to post a user-visible
 * status without direct access to {@code ConfigPanel}. The most recently registered listener wins.
 * This utility is process-local and thread-safe.</p>
 */
public final class ControlStatusBridge {

    private static final AtomicReference<Consumer<String>> LISTENER = new AtomicReference<>();

    private ControlStatusBridge() { }

    /**
     * Registers the current control-status listener.
     *
     * <p>Callers typically register from the EDT via {@code ConfigPanel}. Any previously
     * registered listener is replaced.</p>
     *
     * @param listener consumer that accepts user-visible status text; may be {@code null}
     */
    public static void register(Consumer<String> listener) {
        LISTENER.set(listener);
    }

    /**
     * Clears the registered listener.
     *
     * <p>Used by test reset paths and any runtime teardown that should stop background status
     * delivery.</p>
     */
    public static void clear() {
        LISTENER.set(null);
    }

    /**
     * Posts a status message when a listener is registered.
     *
     * <p>Blank messages are ignored. This method does not enforce EDT delivery; the registered
     * listener is responsible for marshaling to the correct thread when needed.</p>
     *
     * @param message user-visible status text
     */
    public static void post(String message) {
        Consumer<String> listener = LISTENER.get();
        if (listener != null && message != null && !message.isBlank()) {
            listener.accept(message);
        }
    }
}
