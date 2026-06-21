package ai.attackframework.tools.burp.sinks;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Rolls up compressed-wire BODY parameter corrections for operator analysis.
 *
 * <p>Emits INFO summaries at startup backlog complete and Stop, DEBUG samples and periodic
 * roll-ups during live export, and WARN on first live replace or skip-path rescue per URL.</p>
 */
public final class CompressedWireBodyParamsLog {

    /** Live periodic summary interval while export is running. */
    static final int PERIODIC_INTERVAL_SECONDS = 60;

    /** Maximum URLs listed per category on DEBUG startup/stop summaries. */
    static final int URL_SAMPLE_CAP = 10;

    /** Categories recorded for compressed-wire BODY parameter analysis. */
    enum Category {
        /** Burp wire BODY rows replaced by supplemental logical parse. */
        REPLACED,
        /** Wire transformed; supplemental empty; Burp BODY rows dropped. */
        WIRE_DROPPED,
        /** Supplemental BODY added when Burp enumerated none (uncompressed wire path). */
        SUPPLEMENTAL_ADDED,
        /** BODY enumeration was skipped, but urlencoded logical bytes still produced supplemental BODY rows. */
        SKIP_RESCUED
    }

    private static final Object LOCK = new Object();
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-compressed-wire-body-params-log");

    private static final Map<Category, Integer> STARTUP_DOC_COUNTS = new EnumMap<>(Category.class);
    private static final Map<Category, Map<String, Integer>> STARTUP_URLS = new EnumMap<>(Category.class);
    private static final Map<Category, Integer> LIVE_PENDING_DOC_COUNTS = new EnumMap<>(Category.class);
    private static final Map<Category, Map<String, Integer>> LIVE_PENDING_URLS = new EnumMap<>(Category.class);
    private static final Set<String> LIVE_WARNED_URLS = ConcurrentHashMap.newKeySet();

    private static boolean startupSummaryEmitted;
    private static boolean startupAccumulationActive;

    private CompressedWireBodyParamsLog() {}

    /** Clears per-run aggregation state without logging. */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            clearCategoryMaps(STARTUP_DOC_COUNTS, STARTUP_URLS);
            clearCategoryMaps(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
            LIVE_WARNED_URLS.clear();
            startupSummaryEmitted = false;
            startupAccumulationActive = true;
        }
    }

    /**
     * Starts the periodic live summary scheduler.
     *
     * <p>Safe to call from any thread. No-op when already started.</p>
     */
    public static void startPeriodicFlusher() {
        if (SCHEDULER.isStarted()) {
            return;
        }
        synchronized (CompressedWireBodyParamsLog.class) {
            if (SCHEDULER.isStarted()) {
                return;
            }
            SCHEDULER.getOrStart().scheduleAtFixedRate(
                    CompressedWireBodyParamsLog::flushPeriodicSummary,
                    PERIODIC_INTERVAL_SECONDS,
                    PERIODIC_INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
        }
    }

    /**
     * Flushes pending live summary, stops the periodic scheduler, and clears live state.
     *
     * <p>Call from export Stop before clearing run state.</p>
     */
    public static void stopPeriodicFlusher() {
        flushStopSummary();
        SCHEDULER.stop();
    }

    /** Clears state without emitting; used during test and lifecycle resets. */
    public static void clearRunState() {
        stopPeriodicFlusher();
        startForCurrentRun();
    }

    /**
     * Records one compressed-wire BODY parameter correction event.
     *
     * @param request source request
     * @param service optional HTTP service for URL reconstruction
     * @param requestDoc built request sub-document
     * @param category correction category
     */
    public static void record(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            Category category) {
        if (category == null) {
            return;
        }
        String dedupeUrl = dedupeUrl(request, service, requestDoc);
        boolean liveWarn;
        synchronized (LOCK) {
            if (startupAccumulationActive) {
                STARTUP_DOC_COUNTS.compute(category, (k, v) -> v == null ? 1 : v + 1);
                urlBucketFor(STARTUP_URLS, category).compute(dedupeUrl, (k, v) -> v == null ? 1 : v + 1);
                liveWarn = false;
            } else {
                LIVE_PENDING_DOC_COUNTS.compute(category, (k, v) -> v == null ? 1 : v + 1);
                urlBucketFor(LIVE_PENDING_URLS, category).compute(dedupeUrl, (k, v) -> v == null ? 1 : v + 1);
                liveWarn = category == Category.REPLACED || category == Category.SKIP_RESCUED;
            }
        }
        if (liveWarn) {
            maybeWarnLive(dedupeUrl, category);
        }
    }

    /**
     * Emits startup/backlog INFO and DEBUG summaries when any events were recorded.
     *
     * <p>Safe to call multiple times; only the first emission logs.</p>
     */
    public static void flushStartupSummary() {
        String infoLine;
        List<String> debugLines;
        synchronized (LOCK) {
            startupAccumulationActive = false;
            infoLine = null;
            debugLines = List.of();
            if (!startupSummaryEmitted && hasAnyDocs(STARTUP_DOC_COUNTS)) {
                startupSummaryEmitted = true;
                infoLine = formatInfoSummaryLocked("startup/backlog", STARTUP_DOC_COUNTS);
                debugLines = formatDebugSamplesLocked(STARTUP_DOC_COUNTS, STARTUP_URLS);
                clearCategoryMaps(STARTUP_DOC_COUNTS, STARTUP_URLS);
            }
        }
        if (infoLine != null) {
            Logger.logInfoPanelOnly(infoLine);
        }
        for (String line : debugLines) {
            Logger.logDebug(line);
        }
    }

    /** Emits a DEBUG summary for live events accumulated since the last periodic flush. */
    public static void flushPeriodicSummary() {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        String infoLine;
        List<String> debugLines;
        synchronized (LOCK) {
            if (!hasAnyDocs(LIVE_PENDING_DOC_COUNTS)) {
                return;
            }
            infoLine = formatInfoSummaryLocked("live", LIVE_PENDING_DOC_COUNTS);
            debugLines = formatDebugSamplesLocked(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
            clearCategoryMaps(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
        }
        if (infoLine != null) {
            Logger.logInfoPanelOnly(infoLine);
        }
        for (String line : debugLines) {
            Logger.logDebug(line);
        }
    }

    /** Emits final DEBUG summaries for live events not yet flushed. */
    public static void flushStopSummary() {
        flushStopDebugSamples();
    }

    /**
     * Emits DEBUG URL samples for live compressed-wire events not yet flushed.
     *
     * <p>Session totals are INFO from {@link ParameterIntegritySessionLog}.</p>
     */
    public static void flushStopDebugSamples() {
        List<String> debugLines;
        synchronized (LOCK) {
            debugLines = List.of();
            if (hasAnyDocs(LIVE_PENDING_DOC_COUNTS)) {
                debugLines = formatDebugSamplesLocked(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
                clearCategoryMaps(LIVE_PENDING_DOC_COUNTS, LIVE_PENDING_URLS);
            }
        }
        for (String line : debugLines) {
            Logger.logDebug(line);
        }
    }

    static String formatInfoSummaryForTests(String phase, Map<Category, Integer> docCounts) {
        synchronized (LOCK) {
            return formatInfoSummaryLocked(phase, docCounts);
        }
    }

    private static void maybeWarnLive(String url, Category category) {
        String key = category.name() + "|" + url;
        if (!LIVE_WARNED_URLS.add(key)) {
            return;
        }
        String label = category == Category.SKIP_RESCUED ? "skip-path BODY params rescued" : "compressed-wire BODY params replaced";
        Logger.logWarnPanelOnly("[ParameterIntegrity] " + label + " for request.url=" + truncateUrl(url));
    }

    private static String formatInfoSummaryLocked(String phase, Map<Category, Integer> docCounts) {
        int replaced = docCounts.getOrDefault(Category.REPLACED, 0);
        int dropped = docCounts.getOrDefault(Category.WIRE_DROPPED, 0);
        int supplemental = docCounts.getOrDefault(Category.SUPPLEMENTAL_ADDED, 0);
        int rescued = docCounts.getOrDefault(Category.SKIP_RESCUED, 0);
        if (replaced + dropped + supplemental + rescued <= 0) {
            return null;
        }
        return "[ParameterIntegrity] Compressed-wire BODY params during " + phase + ": replaced=" + replaced
                + ", wire_dropped=" + dropped + ", supplemental_added=" + supplemental + ", skip_rescued=" + rescued
                + ". See Stats → Parameter Integrity session totals.";
    }

    private static List<String> formatDebugSamplesLocked(
            Map<Category, Integer> docCounts,
            Map<Category, Map<String, Integer>> urlCounts) {
        List<String> lines = new ArrayList<>();
        for (Category category : Category.values()) {
            int count = docCounts.getOrDefault(category, 0);
            if (count <= 0) {
                continue;
            }
            Map<String, Integer> urls = urlCounts.get(category);
            if (urls == null || urls.isEmpty()) {
                continue;
            }
            List<String> samples = sampleUrls(urls);
            StringBuilder sb = new StringBuilder(200);
            sb.append("[ParameterIntegrity] ").append(category.name()).append(" sample request.url(s) (")
                    .append(count)
                    .append(" doc(s)): ")
                    .append(String.join(", ", samples));
            if (urls.size() > samples.size()) {
                sb.append(", ...");
            }
            sb.append('.');
            lines.add(sb.toString());
        }
        return lines;
    }

    private static List<String> sampleUrls(Map<String, Integer> urlCounts) {
        List<String> samples = new ArrayList<>(Math.min(URL_SAMPLE_CAP, urlCounts.size()));
        for (String url : urlCounts.keySet()) {
            if (samples.size() >= URL_SAMPLE_CAP) {
                break;
            }
            samples.add(truncateUrl(url));
        }
        return samples;
    }

    private static boolean hasAnyDocs(Map<Category, Integer> docCounts) {
        for (Integer count : docCounts.values()) {
            if (count != null && count > 0) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, Integer> urlBucketFor(Map<Category, Map<String, Integer>> urls, Category category) {
        return urls.computeIfAbsent(category, ignored -> new LinkedHashMap<>());
    }

    private static void clearCategoryMaps(
            Map<Category, Integer> docCounts,
            Map<Category, Map<String, Integer>> urlCounts) {
        docCounts.clear();
        urlCounts.clear();
    }

    private static String dedupeUrl(HttpRequest request, HttpService service, Map<String, Object> requestDoc) {
        String direct = RequestResponseDocBuilder.safeRequestUrl(request, "CompressedWireBodyParams");
        if (direct != null) {
            return direct;
        }
        String rebuilt = RequestResponseDocBuilder.buildBestEffortUrl(
                request, service, requestDoc, "CompressedWireBodyParams");
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
