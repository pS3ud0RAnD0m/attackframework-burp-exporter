package ai.attackframework.tools.burp.utils;

import burp.api.montoya.logging.Logging;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * - Delegates to SLF4J so levels/appenders are configurable.
 * - Mirrors to Burp's Logging when available.
 * - Exposes a listener bus consumed by LogPanel and tests.
 * - Contains a Logback appender (nested class) that forwards non-internal SLF4J events to the listener bus.
 */
public final class Logger {

    /** Listener contract used by LogPanel and tests. */
    public interface LogListener {
        void onLog(String level, String message);
    }

    private static final String INTERNAL_LOGGER_NAME = "ai.attackframework.tools.burp";

    private static final org.slf4j.Logger LOG =
            LoggerFactory.getLogger(INTERNAL_LOGGER_NAME);

    private static final List<LogListener> LISTENERS = new CopyOnWriteArrayList<>();

    /** Burp's Montoya logger; set during extension init. */
    private static final AtomicReference<Logging> BURP_LOGGER = new AtomicReference<>();

    private Logger() {}

    /** Wires Burp's Logging sink. Call from extension init. */
    public static void initialize(Logging montoyaLogging) {
        BURP_LOGGER.set(montoyaLogging);
    }

    // Listener management

    public static void registerListener(LogListener listener) {
        if (listener != null) LISTENERS.add(listener);
    }

    public static void unregisterListener(LogListener listener) {
        LISTENERS.remove(listener);
    }

    // Public API

    public static void logInfo(String msg) {
        final String m = safe(msg);
        LOG.info(m);
        toBurpOut(m);
        notifyListeners("INFO", m);
    }

    public static void logWarn(String msg) {
        final String m = safe(msg);
        LOG.warn(m);
        toBurpOut(m);
        notifyListeners("WARN", m);
    }

    public static void logDebug(String msg) {
        final String m = safe(msg);
        LOG.debug(m);
        toBurpOut(m);
        notifyListeners("DEBUG", m);
    }

    public static void logTrace(String msg) {
        final String m = safe(msg);
        LOG.trace(m);
        toBurpOut(m);
        notifyListeners("TRACE", m);
    }

    public static void logError(String msg) {
        final String m = safe(msg);
        LOG.error(m);
        toBurpErr(m);
        notifyListeners("ERROR", m);
    }

    public static void logError(String msg, Throwable t) {
        final String base = safe(msg);
        final String detail = (t != null
                ? " :: " + t.getClass().getSimpleName() + ": " + safe(t.getMessage())
                : "");
        final String uiMessage = base + detail;

        // Log to SLF4J with throwable (stack trace handled by backend)
        LOG.error(base, t);

        // Mirror to Burp + listener bus with a concise exception summary for UI/tests
        toBurpErr(uiMessage);
        notifyListeners("ERROR", uiMessage);
    }

    /** Allows logging backends to forward events into the UI listener bus. */
    public static void emitToListeners(String level, String message) {
        notifyListeners(level, safe(message));
    }

    // Internals

    private static void toBurpOut(String m) {
        Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToOutput(m); } catch (RuntimeException ex) { LOG.debug("Burp logToOutput failed: {}", ex.toString()); }
        }
    }

    private static void toBurpErr(String m) {
        Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToError(m); } catch (RuntimeException ex) { LOG.debug("Burp logToError failed: {}", ex.toString()); }
        }
    }

    private static void notifyListeners(String level, String m) {
        for (LogListener l : LISTENERS) {
            try { l.onLog(level, m); } catch (RuntimeException ex) { LOG.debug("Listener threw: {}", ex.toString()); }
        }
    }

    private static String safe(String s) {
        return Objects.toString(s, "");
    }

    // --------------------------------------------
    // Logback appender that feeds the listener bus
    // --------------------------------------------

    public static final class UiAppender extends ch.qos.logback.core.AppenderBase<ch.qos.logback.classic.spi.ILoggingEvent> {
        @Override
        protected void append(ch.qos.logback.classic.spi.ILoggingEvent event) {
            if (event == null) return;

            // Skip messages from our internal logger; those already notify the UI directly.
            if (INTERNAL_LOGGER_NAME.equals(event.getLoggerName())) {
                return;
            }

            String level = (event.getLevel() != null) ? event.getLevel().toString() : "INFO";
            String message = event.getFormattedMessage();
            if (message == null) message = "";

            var tp = event.getThrowableProxy();
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
