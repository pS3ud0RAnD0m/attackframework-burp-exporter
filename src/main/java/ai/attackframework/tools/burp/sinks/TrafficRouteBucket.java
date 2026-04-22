package ai.attackframework.tools.burp.sinks;

import java.util.Map;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Centralized traffic "route bucket" mapping shared by all traffic sinks and stats views.
 *
 * <p>Traffic exports can be attributed to either:
 * <ul>
 *   <li>a {@link Kind#TOOL_TYPE} bucket (for example {@code REPEATER_HISTORY}, {@code PROXY}),
 *       which aligns with the live {@code tool_type} field Burp assigns to HTTP exchanges; or</li>
 *   <li>a {@link Kind#SOURCE} bucket (for example {@code proxy_history_snapshot},
 *       {@code proxy_websocket}), which aligns with the reporter or source that produced the
 *       document rather than the requesting Burp tool.</li>
 * </ul>
 *
 * <p>Keeping the decision in one place ensures OpenSearch bulk accounting, file-sink accounting,
 * and {@code StatsPanel} display all agree about which bucket a given document belongs to.
 * Sinks should build a {@link Route} once and use the record/resolve helpers here instead of
 * re-implementing the {@code tool_type} -> bucket mapping locally.</p>
 */
public final class TrafficRouteBucket {

    /** Bucket kind used to group traffic counters in stats. */
    public enum Kind {
        /** Grouped by originating reporter/source (for example {@code proxy_history_snapshot}). */
        SOURCE,
        /** Grouped by Burp tool type (for example {@code REPEATER_HISTORY}). */
        TOOL_TYPE
    }

    /**
     * Route record carrying the resolved bucket kind and key.
     *
     * @param kind bucket kind; must not be {@code null}
     * @param key bucket key (tool-type name or source label); must not be {@code null} or blank
     * @throws IllegalArgumentException if {@code kind} is {@code null} or {@code key} is
     *         {@code null} or blank
     */
    public record Route(Kind kind, String key) {
        public Route {
            if (kind == null) {
                throw new IllegalArgumentException("kind must not be null");
            }
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("key must not be blank");
            }
        }
    }

    /** Source key for snapshot-pushed Proxy History items. */
    public static final String SOURCE_PROXY_HISTORY_SNAPSHOT = "proxy_history_snapshot";
    /** Source key for Proxy WebSocket items. */
    public static final String SOURCE_PROXY_WEBSOCKET = "proxy_websocket";
    /** Fallback tool-type key when a document does not declare a tool. */
    public static final String TOOL_TYPE_UNKNOWN = "UNKNOWN";
    /** Logical index key used by the traffic sink in {@link ExportStats} and {@link FileExportStats}. */
    public static final String INDEX_KEY = "traffic";

    private TrafficRouteBucket() {}

    /**
     * Resolves the configured traffic index name.
     *
     * <p>Shared by all traffic reporters so the index-name lookup lives in one place instead of
     * being re-implemented with private copy-paste helpers.</p>
     */
    public static String trafficIndexName() {
        return RuntimeConfig.indexNameForKey(INDEX_KEY);
    }

    /**
     * Resolves the route for a traffic document by inspecting its {@code tool_type} field.
     *
     * @param document a prepared traffic document; {@code null} resolves to {@link #TOOL_TYPE_UNKNOWN}
     * @return resolved route; never {@code null}
     */
    public static Route fromDocument(Map<String, Object> document) {
        if (document == null) {
            return new Route(Kind.TOOL_TYPE, TOOL_TYPE_UNKNOWN);
        }
        Object raw = document.get("tool_type");
        return fromToolType(raw == null ? null : String.valueOf(raw));
    }

    /**
     * Resolves the route for a tool-type string (for example the name of a
     * {@link burp.api.montoya.core.ToolType} constant or a reporter-assigned value).
     *
     * @param toolType tool-type label; {@code null} or blank resolves to {@link #TOOL_TYPE_UNKNOWN}
     * @return resolved route; never {@code null}
     */
    public static Route fromToolType(String toolType) {
        if (toolType == null || toolType.isBlank()) {
            return new Route(Kind.TOOL_TYPE, TOOL_TYPE_UNKNOWN);
        }
        String normalized = toolType.trim();
        if ("PROXY_HISTORY".equals(normalized)) {
            return new Route(Kind.SOURCE, SOURCE_PROXY_HISTORY_SNAPSHOT);
        }
        if ("PROXY_WEBSOCKET".equals(normalized)) {
            return new Route(Kind.SOURCE, SOURCE_PROXY_WEBSOCKET);
        }
        return new Route(Kind.TOOL_TYPE, normalized);
    }

    /** Convenience route for Proxy History snapshot pushes. */
    public static Route proxyHistorySnapshot() {
        return new Route(Kind.SOURCE, SOURCE_PROXY_HISTORY_SNAPSHOT);
    }

    /** Convenience route for Proxy WebSocket messages. */
    public static Route proxyWebSocket() {
        return new Route(Kind.SOURCE, SOURCE_PROXY_WEBSOCKET);
    }

    /** Records {@code count} successful OpenSearch pushes for {@code route}. */
    public static void recordOpenSearchSuccess(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourceSuccess(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypeSuccess(route.key(), count);
        }
    }

    /** Records {@code count} failed OpenSearch pushes for {@code route}. */
    public static void recordOpenSearchFailure(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourceFailure(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypeFailure(route.key(), count);
        }
    }

    /**
     * Records a traffic bulk outcome for OpenSearch, consolidating the success/failure bookkeeping
     * used by one-shot snapshot reporters (Proxy History, Proxy WebSocket).
     *
     * <p>Delegates the index-key totals and panel/error reporting to
     * {@link BulkOutcomeRecorder#record(String, String, String, int, int, boolean)} so traffic
     * and non-traffic reporters share the same log and error shape, then adds the
     * per-route counter updates on top via {@link #recordOpenSearchSuccess(Route, long)} /
     * {@link #recordOpenSearchFailure(Route, long)}.</p>
     *
     * <p>Counts are clamped so {@code sent} is bounded to {@code [0, max(0, attempted)]}; this
     * mirrors {@link BulkOutcomeRecorder} and keeps per-route counters consistent with the index
     * totals when callers mis-report.</p>
     *
     * <p>When {@code openSearchActive} is {@code false}, this call is a no-op and no counters
     * are updated (the file sink records its own outcomes separately).</p>
     *
     * @param route route for the bulk; {@code null} resolves to a no-op
     * @param attempted number of documents attempted in the bulk; negative values are clamped to 0
     * @param sent number of documents acknowledged successful by OpenSearch; clamped to
     *             {@code [0, max(0, attempted)]}
     * @param openSearchActive whether the OpenSearch sink was active for this bulk
     * @param logLabel short label for log messages (for example {@code "Proxy history chunk"})
     */
    public static void recordBulkOutcome(
            Route route,
            int attempted,
            int sent,
            boolean openSearchActive,
            String logLabel) {
        if (route == null) {
            return;
        }
        int clampedAttempted = Math.max(0, attempted);
        int clampedSent = BulkOutcomeRecorder.record(
                INDEX_KEY, "Traffic", logLabel, clampedAttempted, sent, openSearchActive);
        if (!openSearchActive) {
            return;
        }
        if (clampedSent > 0) {
            recordOpenSearchSuccess(route, clampedSent);
        }
        int failure = clampedAttempted - clampedSent;
        if (failure > 0) {
            recordOpenSearchFailure(route, failure);
        }
    }

    /** Records {@code count} successful file writes for {@code route}. */
    public static void recordFileSuccess(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            FileExportStats.recordTrafficSourceSuccess(route.key(), count);
        } else {
            FileExportStats.recordTrafficToolTypeSuccess(route.key(), count);
        }
    }

    /** Records {@code count} failed file writes for {@code route}. */
    public static void recordFileFailure(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            FileExportStats.recordTrafficSourceFailure(route.key(), count);
        } else {
            FileExportStats.recordTrafficToolTypeFailure(route.key(), count);
        }
    }

    /** Returns the current successful OpenSearch push count for {@code route}. */
    public static long openSearchSuccessCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? ExportStats.getTrafficSourceSuccessCount(route.key())
                : ExportStats.getTrafficToolTypeSuccessCount(route.key());
    }

    /** Returns the current failed OpenSearch push count for {@code route}. */
    public static long openSearchFailureCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? ExportStats.getTrafficSourceFailureCount(route.key())
                : ExportStats.getTrafficToolTypeFailureCount(route.key());
    }

    /** Returns the current successful file write count for {@code route}. */
    public static long fileSuccessCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? FileExportStats.getTrafficSourceSuccessCount(route.key())
                : FileExportStats.getTrafficToolTypeSuccessCount(route.key());
    }

    /** Returns the current failed file write count for {@code route}. */
    public static long fileFailureCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? FileExportStats.getTrafficSourceFailureCount(route.key())
                : FileExportStats.getTrafficToolTypeFailureCount(route.key());
    }

    /**
     * Resolves the displayed success count for a "Traffic by source" row in OpenSearch stats.
     *
     * <p>Most rows report the live captured tool-type count. The {@code PROXY_HISTORY} row
     * additionally folds in {@link #SOURCE_PROXY_HISTORY_SNAPSHOT} and {@link #SOURCE_PROXY_WEBSOCKET}
     * so snapshot pushes and proxy WebSocket exports surface under a single Proxy-family row.</p>
     */
    public static long resolveOpenSearchSourceSuccess(String sourceKey) {
        long total = ExportStats.getTrafficToolTypeSuccessCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /** Resolves the displayed failure count for a "Traffic by source" row in OpenSearch stats. */
    public static long resolveOpenSearchSourceFailure(String sourceKey) {
        long total = ExportStats.getTrafficToolTypeFailureCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /** Resolves the displayed success count for a "Traffic by source" row in file stats. */
    public static long resolveFileSourceSuccess(String sourceKey) {
        long total = FileExportStats.getTrafficToolTypeSuccessCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += FileExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += FileExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /** Resolves the displayed failure count for a "Traffic by source" row in file stats. */
    public static long resolveFileSourceFailure(String sourceKey) {
        long total = FileExportStats.getTrafficToolTypeFailureCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += FileExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += FileExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }
}
