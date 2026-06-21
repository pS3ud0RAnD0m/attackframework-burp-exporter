package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Records BODY-parameter truncation for operator logs with startup backlog deduplication and live
 * first-seen warnings.
 *
 * <p>Startup/backlog truncations accumulate by original {@code request.url} until
 * {@link #flushStartupSummary()} runs. Live truncations emit a panel warning the first time each
 * URL is seen during the active export run; additional unique URLs beyond
 * {@link #LIVE_UNIQUE_URL_LOG_CAP} roll into a throttled overflow summary.</p>
 */
public final class BodyParameterTruncationLog {

    /** Maximum distinct live URLs logged individually before switching to overflow summary lines. */
    static final int LIVE_UNIQUE_URL_LOG_CAP = 50;

    /** Maximum startup URLs listed inline on the backlog summary line. */
    static final int STARTUP_URL_SAMPLE_CAP = 10;

    private static final Object LOCK = new Object();
    private static final Set<String> LIVE_LOGGED_URLS = ConcurrentHashMap.newKeySet();
    private static final Map<String, Integer> STARTUP_URL_DROPPED_TOTALS = new LinkedHashMap<>();

    private static int liveUniqueUrlLogsEmitted;
    private static long liveOverflowUniqueUrls;
    private static boolean startupSummaryEmitted;
    /** When {@code true}, truncations accumulate for the startup/backlog summary line. */
    private static boolean startupAccumulationActive;

    private BodyParameterTruncationLog() {}

    /** Clears per-run aggregation state without logging. */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            STARTUP_URL_DROPPED_TOTALS.clear();
            LIVE_LOGGED_URLS.clear();
            liveUniqueUrlLogsEmitted = 0;
            liveOverflowUniqueUrls = 0;
            startupSummaryEmitted = false;
            startupAccumulationActive = true;
        }
    }

    /** Clears state without emitting; used during test and lifecycle resets. */
    public static void clearRunState() {
        startForCurrentRun();
    }

    /**
     * Records one document whose BODY parameters were truncated.
     *
     * @param request source request
     * @param service optional HTTP service for URL reconstruction when {@code request.url()} is unavailable
     * @param requestDoc built request sub-document (may already contain narrowed path/query fields)
     * @param droppedBodyParams number of BODY parameter entries dropped by the cap
     */
    public static void record(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            int droppedBodyParams) {
        if (droppedBodyParams <= 0) {
            return;
        }
        ExportStats.recordBodyParamsTruncated(droppedBodyParams);
        String dedupeUrl = dedupeUrl(request, service, requestDoc);
        if (startupAccumulationActive) {
            recordStartup(dedupeUrl, droppedBodyParams);
        } else {
            recordLive(dedupeUrl, droppedBodyParams);
        }
    }

    /**
     * Emits a deduplicated startup/backlog summary when any startup truncations were recorded.
     *
     * <p>Safe to call multiple times; only the first emission logs.</p>
     */
    public static void flushStartupSummary() {
        String line;
        synchronized (LOCK) {
            startupAccumulationActive = false;
            if (startupSummaryEmitted || STARTUP_URL_DROPPED_TOTALS.isEmpty()) {
                return;
            }
            startupSummaryEmitted = true;
            line = formatStartupSummaryLocked();
        }
        Logger.logInfoPanelOnly(line);
    }

    static String formatStartupSummaryForTests(Map<String, Integer> urlDroppedTotals) {
        synchronized (LOCK) {
            Map<String, Integer> previous = new LinkedHashMap<>(STARTUP_URL_DROPPED_TOTALS);
            try {
                STARTUP_URL_DROPPED_TOTALS.clear();
                STARTUP_URL_DROPPED_TOTALS.putAll(urlDroppedTotals);
                return formatStartupSummaryLocked();
            } finally {
                STARTUP_URL_DROPPED_TOTALS.clear();
                STARTUP_URL_DROPPED_TOTALS.putAll(previous);
            }
        }
    }

    private static void recordStartup(String url, int droppedBodyParams) {
        synchronized (LOCK) {
            STARTUP_URL_DROPPED_TOTALS.compute(url, (k, v) -> v == null ? droppedBodyParams : v + droppedBodyParams);
        }
    }

    private static void recordLive(String url, int droppedBodyParams) {
        if (LIVE_LOGGED_URLS.add(url)) {
            if (liveUniqueUrlLogsEmitted < LIVE_UNIQUE_URL_LOG_CAP) {
                liveUniqueUrlLogsEmitted++;
                Logger.logWarnPanelOnly(formatLiveLine(url, droppedBodyParams));
                return;
            }
            liveOverflowUniqueUrls++;
            maybeEmitLiveOverflowSummary();
            return;
        }
        maybeEmitLiveOverflowSummary();
    }

    private static void maybeEmitLiveOverflowSummary() {
        if (liveOverflowUniqueUrls <= 0 || liveOverflowUniqueUrls % 25 != 0) {
            return;
        }
        Logger.logWarnPanelOnly("[ParameterIntegrity] BODY parameters truncated for "
                + liveOverflowUniqueUrls
                + " additional unique request.url value(s) this run (cap="
                + RequestResponseParametersSupport.BODY_PARAMETERS_CAP
                + "); see Stats for session totals.");
    }

    private static String formatLiveLine(String url, int droppedBodyParams) {
        return "[ParameterIntegrity] BODY parameters truncated to "
                + RequestResponseParametersSupport.BODY_PARAMETERS_CAP
                + " for request.url="
                + truncateUrl(url)
                + "; dropped_body_params="
                + droppedBodyParams
                + " (request.parameters incomplete; body.b64 is complete).";
    }

    private static String formatStartupSummaryLocked() {
        long totalDropped = 0L;
        for (int dropped : STARTUP_URL_DROPPED_TOTALS.values()) {
            totalDropped += dropped;
        }
        StringBuilder sb = new StringBuilder(240);
        sb.append("[StartupExport] BODY parameters truncated for ")
                .append(STARTUP_URL_DROPPED_TOTALS.size())
                .append(" unique request.url(s); cap=")
                .append(RequestResponseParametersSupport.BODY_PARAMETERS_CAP)
                .append("; dropped_body_params=")
                .append(totalDropped);
        List<String> samples = sampleStartupUrls();
        if (!samples.isEmpty()) {
            sb.append("; urls=").append(String.join(", ", samples));
            if (STARTUP_URL_DROPPED_TOTALS.size() > samples.size()) {
                sb.append(", ...");
            }
        }
        sb.append('.');
        return sb.toString();
    }

    private static List<String> sampleStartupUrls() {
        List<String> samples = new ArrayList<>(Math.min(STARTUP_URL_SAMPLE_CAP, STARTUP_URL_DROPPED_TOTALS.size()));
        for (String url : STARTUP_URL_DROPPED_TOTALS.keySet()) {
            if (samples.size() >= STARTUP_URL_SAMPLE_CAP) {
                break;
            }
            samples.add(truncateUrl(url));
        }
        return samples;
    }

    private static String dedupeUrl(HttpRequest request, HttpService service, Map<String, Object> requestDoc) {
        String direct = RequestResponseDocBuilder.safeRequestUrl(request, "BodyParameterCap");
        if (direct != null) {
            return direct;
        }
        String rebuilt = RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "BodyParameterCap");
        if (rebuilt != null) {
            return rebuilt;
        }
        String path = RequestResponseDocBuilder.requestPathWithQuery(requestDoc);
        return path == null ? "unknown" : path;
    }

    private static String truncateUrl(String url) {
        if (url == null) {
            return "unknown";
        }
        if (url.length() <= RequestResponseParametersSupport.PARAMETERS_WARN_URL_MAX_LEN) {
            return url;
        }
        return url.substring(0, RequestResponseParametersSupport.PARAMETERS_WARN_URL_MAX_LEN) + "...";
    }
}
