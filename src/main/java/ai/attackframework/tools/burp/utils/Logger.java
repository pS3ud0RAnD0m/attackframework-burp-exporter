package ai.attackframework.tools.burp.utils;

import burp.api.montoya.logging.Logging;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;
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
    public interface LogListener { void onLog(String level, String message); }

    private static final String INTERNAL_LOGGER_NAME = "ai.attackframework.tools.burp";

    private static final org.slf4j.Logger LOG =
            LoggerFactory.getLogger(INTERNAL_LOGGER_NAME);

    private static final List<LogListener> LISTENERS = new CopyOnWriteArrayList<>();
    private static final AtomicReference<Logging> BURP_LOGGER = new AtomicReference<>();

    private Logger() {}

    /** Wires Burp's Logging sink. */
    public static void initialize(Logging montoyaLogging) { BURP_LOGGER.set(montoyaLogging); }

    public static void registerListener(LogListener listener) { if (listener != null) LISTENERS.add(listener); }
    public static void unregisterListener(LogListener listener) { LISTENERS.remove(listener); }

    // -------- Public API (mirrored to UI listener bus) --------

    public static void logInfo(String msg)  {
        final String m = safe(msg);
        LOG.info(m);
        toBurpOut(m);
        notifyListeners("INFO",  m);
    }

    public static void logWarn(String msg)  {
        final String m = safe(msg);
        LOG.warn(m);
        toBurpOut(m);
        notifyListeners("WARN",  m);
    }

    public static void logDebug(String msg) {
        final String m = safe(msg);
        if (LOG.isDebugEnabled()) LOG.debug(m);
        toBurpOut(m);
        notifyListeners("DEBUG", m);
    }

    public static void logTrace(String msg) {
        final String m = safe(msg);
        if (LOG.isTraceEnabled()) LOG.trace(m);
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
        final String detail = (t != null ? " :: " + t.getClass().getSimpleName() + ": " + safe(t.getMessage()) : "");
        final String uiMessage = base + detail;
        LOG.error(base, t);                    // stack trace handled by backend
        toBurpErr(uiMessage);                  // concise summary mirrored to UI
        notifyListeners("ERROR", uiMessage);
    }

    /** Allows logging backends to forward events into the UI listener bus. */
    public static void emitToListeners(String level, String message) {
        notifyListeners(level, safe(message));
    }

    // -------- Internal-only API (NO UI mirroring) --------
    // Use these inside components like LogPanel to avoid self-feeding the UI listener bus.

    public static void internalInfo(String msg)  { if (LOG.isInfoEnabled())  LOG.info(safe(msg)); }
    public static void internalWarn(String msg)  { if (LOG.isWarnEnabled())  LOG.warn(safe(msg)); }
    public static void internalDebug(String msg) { if (LOG.isDebugEnabled()) LOG.debug(safe(msg)); }
    public static void internalTrace(String msg) { if (LOG.isTraceEnabled()) LOG.trace(safe(msg)); }

    // -------- Internals --------

    private static void toBurpOut(String m) {
        final Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToOutput(m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("logToOutput failed: {}", ex.toString());
            }
        }
    }

    private static void toBurpErr(String m) {
        final Logging l = BURP_LOGGER.get();
        if (l != null) {
            try { l.logToError(m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("logToError failed: {}", ex.toString());
            }
        }
    }

    private static void notifyListeners(String level, String m) {
        for (LogListener l : LISTENERS) {
            try { l.onLog(level, m); }
            catch (RuntimeException ex) {
                if (LOG.isDebugEnabled()) LOG.debug("listener threw: {}", ex.toString());
            }
        }
    }

    private static String safe(String s) { return Objects.toString(s, ""); }

    // --------------------------------------------
    // Logback appender that feeds the listener bus
    // --------------------------------------------

    public static final class UiAppender extends AppenderBase<ILoggingEvent> {
        @Override
        protected void append(ILoggingEvent event) {
            if (event == null) return;

            // Skip messages from our internal logger; those already notify the UI directly.
            if (INTERNAL_LOGGER_NAME.equals(event.getLoggerName())) return;

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
