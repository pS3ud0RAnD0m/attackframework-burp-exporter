package ai.attackframework.tools.burp.sinks;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;
import ai.attackframework.tools.burp.utils.concurrent.SnapshotPacing;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
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
 *       for new {@code webSocketId:messageId} keys only; new frames are offered to
 *       {@link TrafficExportQueue}. The poll stops when export stops or {@code proxy} is deselected
 *       ({@link #refreshLivePollScheduleForCurrentState()}). When only Proxy is selected, keys
 *       present at Start are seeded without export so pre-Start frames are not treated as live.</li>
 * </ul>
 *
 * <p>Non-proxy live WebSocket traffic uses {@link ToolWebSocketLiveHandler}.</p>
 */
public final class ProxyWebSocketIndexReporter {

    private static final int LIVE_POLL_INTERVAL_SECONDS = 10;
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;
    private static final int RECENT_PUSHED_KEY_LIMIT = 100_000;

    private static final LazyScheduler HISTORIC_SCHEDULER =
            new LazyScheduler("attackframework-proxy-websocket-historic");
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("attackframework-proxy-websocket-reporter");
    private static final LazyScheduler SEED_SCHEDULER =
            new LazyScheduler("attackframework-proxy-websocket-seeder");
    private static final Set<String> pushedKeys = ConcurrentHashMap.newKeySet();
    private static final Queue<String> pushedKeyOrder = new ConcurrentLinkedQueue<>();
    private static final AtomicBoolean runInProgress = new AtomicBoolean();
    private static final AtomicBoolean seedInProgress = new AtomicBoolean();
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
            startLivePollAfterCurrentHistorySeed(true);
        }
    }

    /**
     * Seeds current Proxy WebSocket history on a daemon worker, then starts live polling.
     *
     * <p>This keeps potentially large {@code webSocketHistory()} scans off Swing callers while
     * still preserving the ordering guarantee that the first live poll runs only after existing
     * history keys have been recorded.</p>
     */
    public static void startLivePollAfterCurrentHistorySeed(boolean includeWhenHistoricSelected) {
        if (!shouldRunLivePoll()) {
            stopLivePollScheduler();
            return;
        }
        if (SCHEDULER.isStarted() || !seedInProgress.compareAndSet(false, true)) {
            return;
        }
        SEED_SCHEDULER.getOrStart().execute(() -> {
            try {
                if (shouldRunLivePoll()) {
                    seedPushedKeysFromCurrentHistory(includeWhenHistoricSelected);
                }
                if (shouldRunLivePoll()) {
                    startLivePoll();
                }
            } finally {
                seedInProgress.set(false);
            }
        });
    }

    /**
     * Stops only the recurring poll scheduler; preserves {@code pushedKeys} for the current run.
     */
    public static void stopLivePollScheduler() {
        SCHEDULER.stop();
    }

    /**
     * Stops the scheduler and clears per-run {@code pushedKeys} state.
     */
    public static void stop() {
        HISTORIC_SCHEDULER.stop();
        SEED_SCHEDULER.stop();
        stopLivePollScheduler();
        clearPushedKeyState();
        liveHistoryCursor = 0;
        liveHistoryTailKey = null;
        runInProgress.set(false);
        seedInProgress.set(false);
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
            Logger.logWarnPanelOnly("[Traffic] Proxy WebSocket historic snapshot failed: " + msg);
        }
    }

    /**
     * Records current {@code webSocketHistory()} keys in {@code pushedKeys} without exporting.
     *
     * <p>Used when {@code proxy} is selected without {@code proxy_history} so the first live poll
     * only exports frames that arrive after Start.</p>
     */
    public static void seedPushedKeysFromCurrentHistory() {
        seedPushedKeysFromCurrentHistory(false);
    }

    private static void seedPushedKeysFromCurrentHistory(boolean includeWhenHistoricSelected) {
        if (!trafficSelectionAllowsLiveProxyWebSocketPoll()) {
            return;
        }
        if (!includeWhenHistoricSelected && trafficSelectionAllowsHistoricWebSockets()) {
            return;
        }
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null) {
            return;
        }
        List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
        liveHistoryCursor = history.size();
        liveHistoryTailKey = lastHistoryKey(history);
        for (ProxyWebSocketMessage msg : history) {
            rememberPushedKey(messageKey(msg));
        }
        if (!history.isEmpty()) {
            Logger.logInfoPanelOnly("[Traffic] Proxy WebSocket live poll seeded " + history.size()
                    + " existing history key(s); only new frames will export.");
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
            Logger.logWarnPanelOnly("[Traffic] Proxy WebSocket live poll failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, boolean pushAll) {
        if (!runInProgress.compareAndSet(false, true)) {
            return;
        }
        try {
            List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
            if (history == null || history.isEmpty()) {
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
        SnapshotPacing.resetCountersForSnapshot();
        int chunkTarget = BatchSizeController.getInstance().getCurrentBatchSize();
        long estBytes = 0;
        List<String> chunkKeys = new ArrayList<>(chunkTarget);
        List<Map<String, Object>> chunkDocs = new ArrayList<>(chunkTarget);
        int processed = 0;
        for (ProxyWebSocketMessage msg : history) {
            if (!shouldRunHistoricSnapshot()) {
                break;
            }
            SnapshotPacing.paceItem(processed);
            processed++;
            Map<String, Object> doc = buildDocument(api, msg);
            if (doc == null) {
                continue;
            }
            long docBytes = BulkPayloadEstimator.estimateBytes(doc);
            boolean sizeCapReached = !chunkDocs.isEmpty() && (estBytes + docBytes) > BULK_MAX_BYTES;
            boolean countCapReached = !chunkDocs.isEmpty() && chunkDocs.size() >= chunkTarget;
            if (sizeCapReached || countCapReached) {
                flushBatch(chunkKeys, chunkDocs);
                chunkKeys.clear();
                chunkDocs.clear();
                estBytes = 0;
            }
            chunkKeys.add(messageKey(msg));
            chunkDocs.add(doc);
            estBytes += docBytes;
        }
        if (shouldRunHistoricSnapshot() && !chunkDocs.isEmpty()) {
            flushBatch(chunkKeys, chunkDocs);
        }
        liveHistoryCursor = Math.max(liveHistoryCursor, history.size());
        liveHistoryTailKey = lastHistoryKey(history);
        Logger.logInfoPanelOnly(SnapshotPacing.summaryLine("ProxyWebSocket")
                + " processed=" + processed);
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
            String key = messageKey(msg);
            if (pushedKeys.contains(key)) {
                nextCursor = i + 1;
                continue;
            }
            Map<String, Object> doc = buildDocument(api, msg);
            if (doc == null) {
                nextCursor = i + 1;
                continue;
            }
            if (TrafficExportQueue.offerAccepted(doc)) {
                rememberPushedKey(key);
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

    private static void flushBatch(List<String> keys, List<Map<String, Object>> docs) {
        String activeBaseUrl = RuntimeConfig.openSearchUrl();
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        int attempted = docs.size();
        int success = OpenSearchClientWrapper.pushBulk(
                activeBaseUrl, TrafficRouteBucket.trafficIndexName(), TrafficRouteBucket.INDEX_KEY, docs);
        TrafficRouteBucket.recordBulkOutcome(
                TrafficRouteBucket.proxyWebSocket(),
                attempted,
                success,
                openSearchActive,
                "Proxy WebSocket bulk push");
        if (success == attempted) {
            keys.forEach(ProxyWebSocketIndexReporter::rememberPushedKey);
        }
    }

    private static void rememberPushedKey(String key) {
        if (key == null || !pushedKeys.add(key)) {
            return;
        }
        pushedKeyOrder.offer(key);
        trimPushedKeysIfNeeded(RECENT_PUSHED_KEY_LIMIT);
    }

    /**
     * Drops oldest dedupe keys when over {@code limit}, but never evicts keys that are still present
     * in the current {@code webSocketHistory()} snapshot (avoids re-exporting frames Burp still holds
     * during long proxy WebSocket sessions).
     */
    static void trimPushedKeysIfNeeded(int limit) {
        if (pushedKeys.size() <= limit) {
            return;
        }
        Set<String> historyKeys = snapshotCurrentHistoryKeys();
        int queueSize = pushedKeyOrder.size();
        int rotations = 0;
        while (pushedKeys.size() > limit && rotations < queueSize) {
            String oldest = pushedKeyOrder.poll();
            if (oldest == null) {
                return;
            }
            rotations++;
            if (historyKeys.contains(oldest)) {
                pushedKeyOrder.offer(oldest);
                continue;
            }
            pushedKeys.remove(oldest);
            rotations = 0;
            queueSize = pushedKeyOrder.size();
        }
        if (pushedKeys.size() > limit) {
            Logger.logWarnPanelOnly("[Traffic] Proxy WebSocket dedupe cache is at " + pushedKeys.size()
                    + " keys (limit " + limit
                    + "); could not evict keys still present in proxy WebSocket history.");
        }
    }

    private static Set<String> snapshotCurrentHistoryKeys() {
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null) {
            return Set.of();
        }
        Set<String> keys = new HashSet<>();
        for (ProxyWebSocketMessage msg : safeWebSocketHistory(api)) {
            String key = messageKey(msg);
            if (key != null) {
                keys.add(key);
            }
        }
        return keys;
    }

    private static void clearPushedKeyState() {
        pushedKeys.clear();
        pushedKeyOrder.clear();
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

