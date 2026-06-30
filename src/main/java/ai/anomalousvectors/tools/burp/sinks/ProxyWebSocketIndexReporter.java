package ai.anomalousvectors.tools.burp.sinks;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;

/**
 * Exports Burp Proxy WebSocket history frames ({@link ProxyWebSocketMessage}) to the traffic index.
 *
 * <ul>
 *   <li><b>Proxy History</b> ({@code proxy_history}): one-shot full {@code webSocketHistory()} export
 *       on Start, then stop.</li>
 *   <li><b>Proxy</b> ({@code proxy}): recurring diff poll (default 10s) of {@code webSocketHistory()}
 *       for frames after the last poll cursor; new frames are offered to
 *       {@link TrafficExportQueue}. The poll stops when export stops or {@code proxy} is deselected
 *       ({@link #refreshLivePollScheduleForCurrentState()}).</li>
 * </ul>
 *
 * <p>Non-proxy live WebSocket traffic uses {@link ToolWebSocketLiveHandler}.</p>
 */
public final class ProxyWebSocketIndexReporter {

    private static final int LIVE_POLL_INTERVAL_SECONDS = 10;
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final LazyScheduler HISTORIC_SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-websocket-historic");
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-websocket-reporter");
    private static final AtomicBoolean runInProgress = new AtomicBoolean();
    private static volatile int liveHistoryCursor;
    private static volatile String liveHistoryTailKey;

    private ProxyWebSocketIndexReporter() {}

    /**
     * Starts the recurring diff poll for live proxy WebSocket frames.
     *
     * <p>No-op unless export is ready, traffic export is enabled, and {@code proxy} is selected.
     * Does not run when only {@code proxy_history} is selected.</p>
     */
    public static void startLivePoll() {
        if (!shouldRunLivePoll()) {
            return;
        }
        SCHEDULER.startRecurring(
                ProxyWebSocketIndexReporter::pushNewItemsOnly,
                LIVE_POLL_INTERVAL_SECONDS,
                LIVE_POLL_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Reconciles the live diff poll with the current runtime traffic selection.
     *
     * <p>Safe to call from any thread. Stops the scheduler when export is stopped, traffic export is
     * disabled, or {@code proxy} is deselected; starts it when newly enabled while export runs.</p>
     */
    public static void refreshLivePollScheduleForCurrentState() {
        if (!shouldRunLivePoll()) {
            stopLivePollScheduler();
            return;
        }
        if (!SCHEDULER.isStarted()) {
            startLivePoll();
        }
    }

    /** Starts live polling when export state allows it (compat entry point for UI startup). */
    public static void startLivePollAfterCurrentHistorySeed(boolean ignoredIncludeWhenHistoricSelected) {
        if (!shouldRunLivePoll()) {
            stopLivePollScheduler();
            return;
        }
        startLivePoll();
    }

    /** Stops only the recurring poll scheduler. */
    public static void stopLivePollScheduler() {
        SCHEDULER.stop();
    }

    /** Stops schedulers and clears per-run poll cursor state. */
    public static void stop() {
        HISTORIC_SCHEDULER.stop();
        stopLivePollScheduler();
        liveHistoryCursor = 0;
        liveHistoryTailKey = null;
        runInProgress.set(false);
    }

    static boolean shouldRunLivePoll() {
        return RuntimeConfig.isExportReady()
                && RuntimeConfig.isAnyTrafficExportEnabled()
                && trafficSelectionAllowsLiveProxyWebSocketPoll();
    }

    private static boolean shouldRunHistoricSnapshot() {
        return RuntimeConfig.isExportReady()
                && RuntimeConfig.isAnyTrafficExportEnabled()
                && trafficSelectionAllowsHistoricWebSockets();
    }

    /**
     * One-shot export of all proxy WebSocket history when {@code proxy_history} is selected.
     */
    public static void pushHistoricSnapshotNow() {
        try {
            if (!shouldRunHistoricSnapshot()) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            MontoyaApi apiRef = api;
            HISTORIC_SCHEDULER.getOrStart().execute(() -> {
                try {
                    if (!shouldRunHistoricSnapshot()) {
                        return;
                    }
                    pushItems(apiRef, true);
                } catch (Throwable ignored) {
                    // Startup/lifecycle races in Burp can transiently null sub-APIs.
                }
            });
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] ProxyWebSocket: historic snapshot failed: " + msg);
        }
    }

    static void pushNewItemsOnly() {
        try {
            if (!shouldRunLivePoll()) {
                stopLivePollScheduler();
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushItems(api, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[LiveTraffic] ProxyWebSocket: live poll failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, boolean pushAll) {
        if (!runInProgress.compareAndSet(false, true)) {
            return;
        }
        try {
            List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
            if (history == null || history.isEmpty()) {
                if (pushAll) {
                    TrafficStartupBacklogSummary.complete(
                            TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                            0,
                            SnapshotSummary.forRoute(TrafficRouteBucket.proxyWebSocket()));
                }
                return;
            }
            if (pushAll) {
                pushHistoricSnapshotItems(api, history);
            } else {
                pushLivePollItems(api, history);
            }
        } finally {
            runInProgress.set(false);
        }
    }

    private static void pushHistoricSnapshotItems(MontoyaApi api, List<ProxyWebSocketMessage> history) {
        long startNs = System.nanoTime();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(route);
        Logger.logInfoPanelOnly("[StartupExport] ProxyWebSocket: exporting history backlog: "
                + history.size() + " frame(s).");
        SnapshotPacing.resetCountersForSnapshot();
        AtomicInteger processed = new AtomicInteger();

        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        String indexName = TrafficRouteBucket.trafficIndexName();
        String indexKey = TrafficRouteBucket.INDEX_KEY;
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        int chunkTarget = SnapshotBatchTuning.initialTarget();
        int buildWorkers = SnapshotExportEngine.defaultBuildWorkers();
        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                history,
                buildWorkers,
                BULK_MAX_BYTES,
                chunkTarget,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                activeBaseUrl,
                indexName,
                indexKey,
                msg -> {
                    if (!shouldRunHistoricSnapshot()) {
                        return null;
                    }
                    SnapshotPacing.paceItem(processed.getAndIncrement());
                    Map<String, Object> doc = buildDocument(api, msg);
                    if (doc == null) {
                        return null;
                    }
                    return ExportDocumentIdentity.prepare(indexName, indexKey, doc);
                },
                (chunk, outcome, nextChunkTarget) -> TrafficRouteBucket.recordBulkOutcome(
                        route,
                        outcome,
                        openSearchActive,
                        "Proxy WebSocket bulk push"));

        liveHistoryCursor = Math.max(liveHistoryCursor, history.size());
        liveHistoryTailKey = lastHistoryKey(history);
        long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_PROXY_WEBSOCKET,
                exportResult.attempted(),
                exportResult.success(),
                durationMs,
                exportResult.finalChunkTarget(),
                exportResult.chunks(),
                exportResult.totalChunkBytes(),
                exportResult.buildWallMs(),
                exportResult.buildCpuMs(),
                exportResult.flushMs(),
                exportResult.fileFlushMs(),
                exportResult.openSearchFlushMs(),
                exportResult.buildWorkers());
        Logger.logDebug(SnapshotPacing.summaryLine("ProxyWebSocket")
                + " attempted=" + exportResult.attempted()
                + " duration_ms=" + durationMs
                + " build_wall_ms=" + exportResult.buildWallMs()
                + " flush_ms=" + exportResult.flushMs());
        SnapshotSummary.logInfo(
                "ProxyWebSocket",
                baseline,
                exportResult.attempted(),
                durationMs,
                exportResult.buildWallMs(),
                exportResult.flushMs(),
                openSearchActive,
                RuntimeConfig.isAnyFileExportEnabled());
        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                exportResult.attempted(),
                baseline);
    }

    private static void pushLivePollItems(MontoyaApi api, List<ProxyWebSocketMessage> history) {
        String currentTailKey = lastHistoryKey(history);
        int startIndex;
        if (history.size() == liveHistoryCursor && Objects.equals(currentTailKey, liveHistoryTailKey)) {
            return;
        }
        if (liveHistoryCursor < 0 || liveHistoryCursor > history.size() || history.size() == liveHistoryCursor) {
            startIndex = 0;
        } else {
            startIndex = liveHistoryCursor;
        }
        int nextCursor = startIndex;
        for (int i = startIndex; i < history.size(); i++) {
            if (!shouldRunLivePoll()) {
                break;
            }
            ProxyWebSocketMessage msg = history.get(i);
            Map<String, Object> doc = buildDocument(api, msg);
            if (doc == null) {
                nextCursor = i + 1;
                continue;
            }
            if (TrafficExportQueue.offerAccepted(doc)) {
                nextCursor = i + 1;
            } else {
                break;
            }
        }
        liveHistoryCursor = nextCursor;
        liveHistoryTailKey = currentTailKey;
    }

    private static String lastHistoryKey(List<ProxyWebSocketMessage> history) {
        if (history == null || history.isEmpty()) {
            return null;
        }
        return messageKey(history.get(history.size() - 1));
    }

    static List<ProxyWebSocketMessage> safeWebSocketHistory(MontoyaApi api) {
        try {
            if (api == null) {
                return List.of();
            }
            var proxy = api.proxy();
            if (proxy == null) {
                return List.of();
            }
            List<ProxyWebSocketMessage> history = proxy.webSocketHistory();
            return history != null ? history : List.of();
        } catch (Throwable ignored) {
            return List.of();
        }
    }

    static Map<String, Object> buildDocument(MontoyaApi api, ProxyWebSocketMessage ws) {
        if (ws == null) {
            return null;
        }
        HttpRequest upgrade = ws.upgradeRequest();
        ZonedDateTime t = ws.time();
        String wsTime = t == null ? null : t.toInstant().toString();
        ByteArray payload = ws.payload();
        ByteArray edited = ws.editedPayload();
        byte[] editedBytes = edited == null ? null : edited.getBytes();
        boolean isEdited = editedBytes != null;
        byte[] payloadBytes = isEdited
                ? editedBytes
                : (payload == null ? null : payload.getBytes());
        return WebSocketTrafficDocumentBuilder.build(new WebSocketTrafficDocumentBuilder.Input(
                api,
                upgrade,
                "ProxyWebSocket",
                "Proxy WebSocket",
                ws.id(),
                ws.listenerPort(),
                ws.webSocketId(),
                ws.id(),
                ws.direction() == null ? null : ws.direction().name(),
                payloadBytes,
                isEdited,
                wsTime,
                ws.annotations() != null && ws.annotations().hasNotes() ? ws.annotations().notes() : null,
                ws.annotations() != null && ws.annotations().hasHighlightColor()
                        ? (ws.annotations().highlightColor() == null ? null : ws.annotations().highlightColor().name())
                        : null));
    }

    static String messageKey(ProxyWebSocketMessage ws) {
        return ws.webSocketId() + ":" + ws.id();
    }

    static boolean trafficSelectionAllowsHistoricWebSockets() {
        List<String> trafficTypes = trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains("proxy_history");
    }

    static boolean trafficSelectionAllowsLiveProxyWebSocketPoll() {
        List<String> trafficTypes = trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains("proxy");
    }

    private static List<String> trafficToolTypes() {
        return RuntimeConfig.getState() == null ? null : RuntimeConfig.getState().trafficToolTypes();
    }

}
