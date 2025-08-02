package ai.attackframework.vectors.sources.burp.utils;

import burp.api.montoya.logging.Logging;

import java.util.ArrayList;
import java.util.List;

public class Logger {

    private static Logging burpLogger;

    public interface LogListener {
        void onLog(String level, String message);
    }

    private static final List<LogListener> listeners = new ArrayList<>();

    public static void initialize(Logging logger) {
        burpLogger = logger;
    }

    public static void registerListener(LogListener listener) {
        listeners.add(listener);
    }

    public static void logInfo(String msg) {
        if (burpLogger != null) {
            burpLogger.logToOutput(msg);
        } else {
            System.out.println(msg);
        }
        notifyListeners("INFO", msg);
    }

    public static void logError(String msg) {
        if (burpLogger != null) {
            burpLogger.logToError(msg);
        } else {
            System.err.println(msg);
        }
        notifyListeners("ERROR", msg);
    }

    private static void notifyListeners(String level, String msg) {
        for (LogListener listener : listeners) {
            listener.onLog(level, msg);
        }
    }
}
