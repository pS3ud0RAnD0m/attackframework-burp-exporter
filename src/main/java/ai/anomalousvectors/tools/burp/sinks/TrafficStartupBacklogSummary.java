package ai.anomalousvectors.tools.burp.sinks;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Aggregates the initial traffic backlog reporters into one startup completion line.
 *
 * <p>Traffic startup work is split across Repeater Tabs, Proxy WebSocket history, and Proxy
 * History. Each reporter owns its source-specific completion log; this coordinator emits a single
 * roll-up once every expected traffic startup component has reported completion.</p>
 */
public final class TrafficStartupBacklogSummary {

    /** Initial traffic backlog components that can contribute to the aggregate line. */
    enum Component {
        REPEATER_TABS("repeater_tabs"),
        PROXY_WEBSOCKET("proxy_websocket"),
        PROXY_HISTORY("proxy_history");

        private final String label;

        Component(String label) {
            this.label = label;
        }
    }

    private static final Object LOCK = new Object();
    private static int generation;
    private static EnumSet<Component> expected = EnumSet.noneOf(Component.class);
    private static EnumMap<Component, ComponentResult> completed = new EnumMap<>(Component.class);
    private static boolean fileActive;
    private static boolean openSearchActive;
    private static boolean logged;

    private TrafficStartupBacklogSummary() {}

    /**
     * Starts a fresh aggregate for the current runtime traffic selection.
     *
     * <p>Call once during Start after runtime config has been captured and before reporters are
     * scheduled.</p>
     */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            generation++;
            expected = expectedComponentsForCurrentConfig();
            completed = new EnumMap<>(Component.class);
            fileActive = RuntimeConfig.isAnyFileExportEnabled();
            openSearchActive = RuntimeConfig.isOpenSearchActive();
            logged = expected.isEmpty();
        }
    }

    /**
     * Returns whether the current run expects traffic startup backlog components.
     *
     * <p>When {@code false}, {@link UrlParameterTruncationLog#flushStartupSummary()} should run at
     * the end of the Start pipeline because no backlog completion line will fire.</p>
     */
    public static boolean hasExpectedStartupComponents() {
        synchronized (LOCK) {
            return !expected.isEmpty();
        }
    }

    /** Clears the aggregate without emitting a completion line. */
    public static void clearRunState() {
        synchronized (LOCK) {
            generation++;
            expected = EnumSet.noneOf(Component.class);
            completed = new EnumMap<>(Component.class);
            fileActive = false;
            openSearchActive = false;
            logged = true;
        }
    }

    /**
     * Marks one startup traffic component complete.
     *
     * <p>Ignored when export is not running, the coordinator was cleared, or the component was not
     * expected for the current run.</p>
     *
     * @param component component that finished
     * @param captured number of source documents captured or attempted by the reporter
     * @param baseline counter baseline captured before that reporter started
     */
    static void complete(Component component, int captured, SnapshotSummary.Baseline baseline) {
        if (component == null) {
            return;
        }
        String line = null;
        synchronized (LOCK) {
            if (!RuntimeConfig.isExportRunning() || logged || !expected.contains(component)) {
                return;
            }
            int runGeneration = generation;
            completed.put(component, ComponentResult.from(captured, baseline));
            if (completed.keySet().containsAll(expected) && runGeneration == generation) {
                logged = true;
                line = formatCompletionLine();
            }
        }
        if (line != null) {
            Logger.logInfoPanelOnly(line);
            UrlParameterTruncationLog.flushStartupSummary();
            BodyParameterTruncationLog.flushStartupSummary();
            BodyEnumerationSkippedLog.flushStartupSummary();
            CompressedWireBodyParamsLog.flushStartupSummary();
        }
    }

    static String formatCompletionLineForTests(
            Map<Component, ComponentResult> componentResults,
            boolean includeFile,
            boolean includeOpenSearch) {
        synchronized (LOCK) {
            EnumSet<Component> previousExpected = expected;
            EnumMap<Component, ComponentResult> previousCompleted = completed;
            boolean previousFileActive = fileActive;
            boolean previousOpenSearchActive = openSearchActive;
            try {
                expected = EnumSet.copyOf(componentResults.keySet());
                completed = new EnumMap<>(componentResults);
                fileActive = includeFile;
                openSearchActive = includeOpenSearch;
                return formatCompletionLine();
            } finally {
                expected = previousExpected;
                completed = previousCompleted;
                fileActive = previousFileActive;
                openSearchActive = previousOpenSearchActive;
            }
        }
    }

    private static EnumSet<Component> expectedComponentsForCurrentConfig() {
        if (!RuntimeConfig.isAnyTrafficExportEnabled()) {
            return EnumSet.noneOf(Component.class);
        }
        EnumSet<Component> components = EnumSet.noneOf(Component.class);
        if (RuntimeConfig.isTrafficToolTypeEnabled("repeater_tabs")) {
            components.add(Component.REPEATER_TABS);
        }
        List<String> trafficTypes = RuntimeConfig.getState() == null
                ? List.of()
                : RuntimeConfig.getState().trafficToolTypes();
        if (trafficTypes != null && trafficTypes.contains("proxy_history")) {
            components.add(Component.PROXY_HISTORY);
            components.add(Component.PROXY_WEBSOCKET);
        }
        return components;
    }

    private static String formatCompletionLine() {
        Totals totals = totals();
        StringBuilder sb = new StringBuilder(160);
        sb.append("[StartupExport] Traffic: backlog complete captured=").append(totals.captured());
        if (fileActive) {
            sb.append("; file={written=").append(totals.fileSuccess())
                    .append(", failure=").append(totals.fileFailure()).append('}');
        }
        if (openSearchActive) {
            sb.append("; openSearch={exported=").append(totals.openSearchSuccess())
                    .append(", failure=").append(totals.openSearchFailure()).append('}');
        }
        sb.append("; components={");
        boolean first = true;
        for (Component component : expected) {
            ComponentResult result = completed.getOrDefault(component, ComponentResult.empty());
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append(component.label).append('=').append(result.captured());
        }
        sb.append("}.");
        return sb.toString();
    }

    private static Totals totals() {
        long captured = 0L;
        long fileSuccess = 0L;
        long fileFailure = 0L;
        long openSearchSuccess = 0L;
        long openSearchFailure = 0L;
        for (Component component : expected) {
            ComponentResult result = completed.getOrDefault(component, ComponentResult.empty());
            captured += result.captured();
            fileSuccess += result.deltas().fileSuccess();
            fileFailure += result.deltas().fileFailure();
            openSearchSuccess += result.deltas().openSearchSuccess();
            openSearchFailure += result.deltas().openSearchFailure();
        }
        return new Totals(captured, fileSuccess, fileFailure, openSearchSuccess, openSearchFailure);
    }

    record ComponentResult(int captured, SnapshotSummary.CompletionDeltas deltas) {

        static ComponentResult from(int captured, SnapshotSummary.Baseline baseline) {
            return new ComponentResult(
                    Math.max(0, captured),
                    SnapshotSummary.completionDeltas(baseline));
        }

        static ComponentResult empty() {
            return new ComponentResult(0, SnapshotSummary.CompletionDeltas.empty());
        }
    }

    private record Totals(
            long captured,
            long fileSuccess,
            long fileFailure,
            long openSearchSuccess,
            long openSearchFailure) {
    }
}
