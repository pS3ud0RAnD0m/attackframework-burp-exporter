package ai.attackframework.vectors.sources.burp.utils;

import burp.api.montoya.logging.Logging;

public class Logger {

    private static Logging burpLogger;

    public static void initialize(Logging logger) {
        burpLogger = logger;
    }

    public static void logInfo(String msg) {
        if (burpLogger != null) {
            burpLogger.logToOutput(msg);
        } else {
            System.out.println(msg);
        }
    }

    public static void logError(String msg) {
        if (burpLogger != null) {
            burpLogger.logToError(msg);
        } else {
            System.err.println(msg);
        }
    }
}
