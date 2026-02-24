package ai.attackframework.tools.burp.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import burp.api.montoya.logging.Logging;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import org.slf4j.LoggerFactory;

/**
 * - Delegates to SLF4J so levels/appenders are configurable.
 * - Mirrors to Burp's Logging when available.
 * - Exposes a listener bus consumed by LogPanel and tests.
 * - Keeps a bounded replay buffer so newly registered listeners (e.g. after tab switch)
 *   receive recent messages and the Log panel shows full history.
 * - Contains a Logback appender (nested class) that forwards non-internal SLF4J events to the listener bus.
 */
public final class Logger {

    /**
     * Listener contract used by LogPanel and tests.
     */
    public interface LogListener { void onLog(String level, String message); }

    private static final String INTERNAL_LOGGER_NAME = "ai.attackframework.tools.burp";
    private static final int REPLAY_BUFFER_SIZE = 500;

    private static final org.slf4j.Logger LOG =
            LoggerFactory.getLogger(INTERNAL_LOGGER_NAME);

    private static final List<LogListener> LISTENERS = new CopyOnWriteArrayList<>();
    private static final AtomicReference<Logging> BURP_LOGGER = new AtomicReference<>();

    /** Bounded replay buffer for new listeners. Guarded by REPLAY_BUFFER_LOCK. */
    private static final Object REPLAY_BUFFER_LOCK = new Object();
    private static final List<ReplayEvent> REPLAY_BUFFER = new ArrayList<>(REPLAY_BUFFER_SIZE);
    private static final AtomicLong REPLAY_SEQ = new AtomicLong(0);
    private static final Map<LogListener, Long> LAST_SEEN =
            Collections.synchronizedMap(new WeakHashMap<>());

    /**
     * Utility holder; not instantiable.
     */
    private Logger() {}

    /**
     * Wires Burp's Logging sink.
     * <p>
     * @param montoyaLogging Burp logging handle
     */
    public static void initialize(Logging montoyaLogging) { BURP_LOGGER.set(montoyaLogging); }

    /**
     * Registers a UI/log listener. If the listener is a {@link ReplayableLogListener},
     * recent buffered messages are replayed so the panel shows full history (e.g. after
     * switching back to the extension tab when Burp had removed the panel).
     *
     * @param listener listener to add (nullable ignored)
     */
    public static void registerListener(LogListener listener) {
        if (listener == null) return;
        if (LISTENERS.contains(listener)) return;
        LISTENERS.add(listener);
        if (listener instanceof ReplayableLogListener) {
            replayTo(listener);
        }
    }

    /**
     * Marker for listeners that should receive a replay of recent messages when registered
     * (e.g. LogPanel so the tab shows full history after a tab switch).
     */
    public interface ReplayableLogListener extends LogListener {}

    /**
     * Unregisters a UI/log listener.
     *
     * @param listener listener to remove (nullable ignored)
     */
    public static void unregisterListener(LogListener listener) { LISTENERS.remove(listener); }

    // -------- Public API (mirrored to UI listener bus) --------

    /**
     * Logs at INFO and mirrors to Burp and UI listeners.
     * <p>
     * @param msg message to log
     */
    public static void logInfo(String msg)  {
        final String m = safe(msg);
        LOG.info(m);
        toBurpOut(m);
        notifyListeners("INFO",  m);
    }

    /**
     * Logs at WARN and mirrors to Burp and UI listeners.
     * <p>
     * @param msg message to log
     */
    public static void logWarn(String msg)  {
        final String m = safe(msg);
        LOG.warn(m);
        toBurpOut(m);
        notifyListeners("WARN",  m);
    }

    /**
     * Logs at DEBUG (when enabled) and mirrors to UI listeners only (not Burp console).
     * <p>
     * @param msg message to log
     */
    public static void logDebug(String msg) {
        final String m = safe(msg);
        if (LOG.isDebugEnabled()) LOG.debug(m);
        notifyListeners("DEBUG", m);
    }

    /**
     * Logs at TRACE (when enabled) and mirrors to UI listeners only (not Burp console).
     * <p>
     * @param msg message to log
     */
    public static void logTrace(String msg) {
        final String m = safe(msg);
        if (LOG.isTraceEnabled()) LOG.trace(m);
        notifyListeners("TRACE", m);
    }

    /**
     * Logs at ERROR and mirrors to Burp and UI listeners.
     * <p>
     * @param msg message to log
     */
    public static void logError(String msg) {
        final String m = safe(msg);
        LOG.error(m);
        toBurpErr(m);
        notifyListeners("ERROR", m);
    }

    /**
     * Logs at ERROR with throwable, mirrors concise summary to Burp/UI listeners.
     * <p>
     * @param msg message to log
     * @param t   throwable (nullable)
     */
    public static void logError(String msg, Throwable t) {
        final String base = safe(msg);
        final String detail = (t != null ? " :: " + t.getClass().getSimpleName() + ": " + safe(t.getMessage()) : "");
        final String uiMessage = base + detail;
        LOG.error(base, t);                    // stack trace handled by backend
        toBurpErr(uiMessage);                  // concise summary mirrored to UI
        notifyListeners("ERROR", uiMessage);
    }

    /**
     * Allows logging backends to forward events into the UI listener bus.
     * <p>
     * @param level   level string
     * @param message message to emit
     */
    public static void emitToListeners(String level, String message) {
        notifyListeners(level, safe(message));
    }

    // -------- Internal-only API (NO UI mirroring) --------
    // Use these inside components like LogPanel to avoid self-feeding the UI listener bus.

    /** Logs at INFO without notifying UI listeners. */
    public static void internalInfo(String msg)  { if (LOG.isInfoEnabled())  LOG.info(safe(msg)); }
    /** Logs at WARN without notifying UI listeners. */
    public static void internalWarn(String msg)  { if (LOG.isWarnEnabled())  LOG.warn(safe(msg)); }
    /** Logs at DEBUG without notifying UI listeners. */
    public static void internalDebug(String msg) { if (LOG.isDebugEnabled()) LOG.debug(safe(msg)); }
    /** Logs at TRACE without notifying UI listeners. */
    public static void internalTrace(String msg) { if (LOG.isTraceEnabled()) LOG.trace(safe(msg)); }

    // -------- Internals --------

    /**
     * Sends a message to Burp's standard output log if available.
     * <p>
     * @param m message to log
     */
    private static void toBurpOut(String m) {
        final Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToOutput(m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("logToOutput failed: {}", ex.toString());
            }
        }
    }

    /**
     * Sends a message to Burp's error log if available.
     * <p>
     * @param m message to log
     */
    private static void toBurpErr(String m) {
        final Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToError(m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("logToError failed: {}", ex.toString());
            }
        }
    }

    /**
     * Dispatches a message to registered UI listeners.
     * Always runs listener callbacks on the EDT so the Log panel (and any Swing
     * listener) updates correctly when log calls come from worker threads.
     *
     * @param level level string
     * @param m     message text
     */
    private static void notifyListeners(String level, String m) {
        long seq = appendToReplayBuffer(level, m);
        if (LISTENERS.isEmpty()) {
            return;
        }
        if (SwingUtilities.isEventDispatchThread()) {
            doNotifyListeners(seq, level, m);
        } else {
            SwingUtilities.invokeLater(() -> doNotifyListeners(seq, level, m));
        }
    }

    private static long appendToReplayBuffer(String level, String m) {
        long seq = REPLAY_SEQ.incrementAndGet();
        synchronized (REPLAY_BUFFER_LOCK) {
            REPLAY_BUFFER.add(new ReplayEvent(seq, level, m));
            while (REPLAY_BUFFER.size() > REPLAY_BUFFER_SIZE) {
                REPLAY_BUFFER.remove(0);
            }
        }
        return seq;
    }

    /**
     * Replays buffered messages to a single listener on the EDT so the panel shows full history.
     */
    private static void replayTo(LogListener listener) {
        long lastSeen = LAST_SEEN.getOrDefault(listener, 0L);
        List<ReplayEvent> snapshot;
        synchronized (REPLAY_BUFFER_LOCK) {
            snapshot = new ArrayList<>(REPLAY_BUFFER);
        }
        if (snapshot.isEmpty()) return;
        List<ReplayEvent> toReplay = new ArrayList<>();
        for (ReplayEvent ev : snapshot) {
            if (ev.seq() > lastSeen) {
                toReplay.add(ev);
            }
        }
        if (toReplay.isEmpty()) return;
        Runnable replay = () -> {
            long latest = lastSeen;
            for (ReplayEvent entry : toReplay) {
                try {
                    listener.onLog(entry.level(), entry.message());
                    latest = entry.seq();
                } catch (RuntimeException ex) {
                    if (LOG.isDebugEnabled()) LOG.debug("replay listener threw: {}", ex.toString());
                }
            }
            if (latest > lastSeen) {
                LAST_SEEN.put(listener, latest);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            replay.run();
        } else {
            SwingUtilities.invokeLater(replay);
        }
    }

    private static void doNotifyListeners(long seq, String level, String m) {
        for (LogListener l : LISTENERS) {
            try {
                l.onLog(level, m);
                if (l instanceof ReplayableLogListener) {
                    LAST_SEEN.put(l, seq);
                }
            } catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("listener threw: {}", ex.toString());
            }
        }
    }

    private record ReplayEvent(long seq, String level, String message) {}

    /**
     * Null-safe string conversion.
     * <p>
     * @param s input string
     * @return non-null string
     */
    private static String safe(String s) { return Objects.toString(s, ""); }

    // --------------------------------------------
    // Logback appender that feeds the listener bus
    // --------------------------------------------

    /**
     * Logback appender that forwards non-internal events to the UI listener bus.
     */
    public static final class UiAppender extends AppenderBase<ILoggingEvent> {
        /**
         * Forwards the event to UI listeners, skipping internal logger entries.
         * <p>
         * @param event logback event
         */
        @Override
        protected void append(ILoggingEvent event) {
            if (event == null) return;

            // Skip messages from our internal logger; those already notify the UI directly.
            if (INTERNAL_LOGGER_NAME.equals(event.getLoggerName())) return;

            // Only forward our package to the UI. Third-party (e.g. org.apache.hc) would flood the panel and cause cap-rebuild loops.
            if (!event.getLoggerName().startsWith("ai.attackframework")) return;

            String level = (event.getLevel() != null) ? event.getLevel().toString() : "INFO";
            String message = event.getFormattedMessage();
            if (message == null) message = "";

            IThrowableProxy tp = event.getThrowableProxy();
            if (tp != null) {
                String exClass = tp.getClassName();
                String exMsg = tp.getMessage();
                message = message + " :: " + (exClass != null ? exClass : "Exception")
                        + (exMsg != null ? (": " + exMsg) : "");
            }

            Logger.emitToListeners(level, message);
        }
    }
}
