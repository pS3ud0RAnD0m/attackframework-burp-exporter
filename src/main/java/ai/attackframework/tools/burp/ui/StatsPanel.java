package ai.attackframework.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.ThreadMXBean;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Timer;
import javax.swing.SwingUtilities;
import javax.swing.text.DefaultCaret;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;

/**
 * Panel that displays live export and JVM metrics for all indexes.
 *
 * <p>Updates every few seconds via a Swing Timer. Shows export state, session
 * totals (all indexes), per-index table (docs pushed, queued, failures, last push ms,
 * last error), and process-wide JVM metrics (Burp + extensions). Caller must construct on the EDT.</p>
 */
public class StatsPanel extends JPanel {

    private static final int REFRESH_INTERVAL_MS = 3000;
    private static final long MEGABYTE = 1024 * 1024;
    private static final int ERROR_COL_MAX = 50;
    private static final int CHART_MAX_POINTS = 240;
    private static final int CHART_PANEL_HEIGHT = 520;
    private static final long CHART_WINDOW_MAX_MS = 60L * 60L * 1000L;
    private static final Font CHART_TITLE_FONT = new Font("SansSerif", Font.BOLD, 14);
    private static final Font CHART_AXIS_LABEL_FONT = new Font("SansSerif", Font.PLAIN, 12);
    private static final Font CHART_TICK_FONT = new Font("SansSerif", Font.PLAIN, 11);
    private static final Color CHART_BG = new Color(38, 38, 38);
    private static final Color PLOT_BG = new Color(48, 48, 48);
    private static final Color TEXT_FG = new Color(235, 235, 235);
    private static final Color GRID_FG = new Color(95, 95, 95);
    private static final Color[] SERIES_COLORS = new Color[] {
            new Color(86, 156, 214),   // blue
            new Color(78, 201, 176),   // teal
            new Color(220, 220, 170),  // yellow
            new Color(197, 134, 192),  // purple
            new Color(244, 71, 71)     // red
    };

    private final JTextArea statsArea;
    private final Timer refreshTimer;
    private final TimeSeriesCollection docsPerSecondDataset;
    private final TimeSeriesCollection kibPerSecondDataset;
    private final JFreeChart docsChart;
    private final JFreeChart kibChart;
    private final Map<String, TimeSeries> docsSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> kibSeriesByIndex = new HashMap<>();
    private final Map<String, Long> previousSuccessByIndex = new HashMap<>();
    private final Map<String, Long> previousBytesByIndex = new HashMap<>();
    private long firstSampleAtMs = -1;
    private long previousSampleAtMs = -1;

    /**
     * Creates the Stats panel and starts the refresh timer.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        docsPerSecondDataset = new TimeSeriesCollection();
        kibPerSecondDataset = new TimeSeriesCollection();
        docsChart = createRateChart(
                "Export Throughput - Documents/sec by Index",
                "Docs per second",
                docsPerSecondDataset);
        kibChart = createRateChart(
                "Export Throughput - Payload KiB/sec by Index",
                "KiB per second",
                kibPerSecondDataset);

        JPanel chartsPanel = new JPanel(new GridLayout(2, 1, 0, 6));
        chartsPanel.add(createRateChartPanel(docsChart));
        chartsPanel.add(createRateChartPanel(kibChart));
        chartsPanel.setPreferredSize(new Dimension(1200, CHART_PANEL_HEIGHT));
        add(chartsPanel, BorderLayout.NORTH);

        statsArea = new JTextArea();
        statsArea.setEditable(false);
        statsArea.setLineWrap(false);
        statsArea.setWrapStyleWord(false);
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        if (statsArea.getCaret() instanceof DefaultCaret caret) {
            caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
        }

        add(ScrollPanes.wrap(statsArea), BorderLayout.CENTER);

        refreshTimer = new Timer(REFRESH_INTERVAL_MS, e -> {
            if (isShowing()) {
                refreshVisibleStats();
            }
        });
        refreshTimer.setRepeats(true);

        refreshVisibleStats();
    }

    private void refreshVisibleStats() {
        sampleRateSeries();
        setStatsTextPreservingScroll(buildStatsText());
    }

    /**
     * Replaces stats text while preserving user's vertical scroll position.
     *
     * <p>When users scroll up to inspect previous lines, periodic refresh should not jump the
     * viewport. If the user is at bottom, keep anchored to bottom after refresh.</p>
     */
    private void setStatsTextPreservingScroll(String text) {
        JScrollPane scrollPane = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, statsArea);
        if (scrollPane == null) {
            statsArea.setText(text);
            return;
        }
        JScrollBar bar = scrollPane.getVerticalScrollBar();
        int oldValue = bar.getValue();
        int oldMaxWithoutExtent = Math.max(0, bar.getMaximum() - bar.getVisibleAmount());
        boolean wasAtBottom = oldValue >= Math.max(0, oldMaxWithoutExtent - 2);

        statsArea.setText(text);
        SwingUtilities.invokeLater(() -> {
            int newMaxWithoutExtent = Math.max(0, bar.getMaximum() - bar.getVisibleAmount());
            if (wasAtBottom) {
                bar.setValue(newMaxWithoutExtent);
                return;
            }
            if (oldMaxWithoutExtent <= 0) {
                bar.setValue(0);
                return;
            }
            double ratio = oldValue / (double) oldMaxWithoutExtent;
            int target = (int) Math.round(ratio * newMaxWithoutExtent);
            bar.setValue(Math.max(0, Math.min(newMaxWithoutExtent, target)));
        });
    }

    private void sampleRateSeries() {
        long now = System.currentTimeMillis();
        if (previousSampleAtMs < 0) {
            previousSampleAtMs = now;
            firstSampleAtMs = now;
            for (String indexKey : ExportStats.getIndexKeys()) {
                previousSuccessByIndex.put(indexKey, ExportStats.getSuccessCount(indexKey));
                previousBytesByIndex.put(indexKey, ExportStats.getExportedBytes(indexKey));
                ensureSeries(indexKey);
            }
            updateChartWindow(now);
            return;
        }

        double elapsedSec = Math.max(0.001, (now - previousSampleAtMs) / 1000.0);
        Millisecond tick = new Millisecond(new Date(now));
        for (String indexKey : ExportStats.getIndexKeys()) {
            ensureSeries(indexKey);
            long currentSuccess = ExportStats.getSuccessCount(indexKey);
            long currentBytes = ExportStats.getExportedBytes(indexKey);
            long previousSuccess = previousSuccessByIndex.getOrDefault(indexKey, currentSuccess);
            long previousBytes = previousBytesByIndex.getOrDefault(indexKey, currentBytes);

            double docsPerSec = Math.max(0.0, (currentSuccess - previousSuccess) / elapsedSec);
            double kibPerSec = Math.max(0.0, (currentBytes - previousBytes) / 1024.0 / elapsedSec);
            docsSeriesByIndex.get(indexKey).addOrUpdate(tick, docsPerSec);
            kibSeriesByIndex.get(indexKey).addOrUpdate(tick, kibPerSec);

            previousSuccessByIndex.put(indexKey, currentSuccess);
            previousBytesByIndex.put(indexKey, currentBytes);
        }
        previousSampleAtMs = now;
        updateChartWindow(now);
    }

    private void ensureSeries(String indexKey) {
        docsSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(key);
            s.setMaximumItemCount(CHART_MAX_POINTS);
            docsPerSecondDataset.addSeries(s);
            return s;
        });
        kibSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(key);
            s.setMaximumItemCount(CHART_MAX_POINTS);
            kibPerSecondDataset.addSeries(s);
            return s;
        });
    }

    private static JFreeChart createRateChart(String title, String yLabel, TimeSeriesCollection dataset) {
        JFreeChart chart = ChartFactory.createTimeSeriesChart(title, "Time", yLabel, dataset, true, false, false);
        chart.setBackgroundPaint(CHART_BG);
        chart.getTitle().setPaint(TEXT_FG);
        chart.getTitle().setFont(CHART_TITLE_FONT);
        XYPlot plot = chart.getXYPlot();
        plot.setBackgroundPaint(PLOT_BG);
        plot.setDomainGridlinePaint(GRID_FG);
        plot.setRangeGridlinePaint(GRID_FG);
        plot.setDomainGridlinesVisible(true);
        plot.setRangeGridlinesVisible(true);
        ValueAxis domain = plot.getDomainAxis();
        ValueAxis range = plot.getRangeAxis();
        domain.setLabelPaint(TEXT_FG);
        range.setLabelPaint(TEXT_FG);
        domain.setTickLabelPaint(TEXT_FG);
        range.setTickLabelPaint(TEXT_FG);
        domain.setLabelFont(CHART_AXIS_LABEL_FONT);
        range.setLabelFont(CHART_AXIS_LABEL_FONT);
        domain.setTickLabelFont(CHART_TICK_FONT);
        range.setTickLabelFont(CHART_TICK_FONT);
        XYLineAndShapeRenderer renderer = (XYLineAndShapeRenderer) plot.getRenderer();
        renderer.setDefaultShapesVisible(false);
        renderer.setDefaultStroke(new BasicStroke(2.0f));
        for (int i = 0; i < SERIES_COLORS.length; i++) {
            renderer.setSeriesPaint(i, SERIES_COLORS[i]);
        }
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(CHART_BG);
            chart.getLegend().setItemPaint(TEXT_FG);
            chart.getLegend().setItemFont(CHART_TICK_FONT);
        }
        return chart;
    }

    private static ChartPanel createRateChartPanel(JFreeChart chart) {
        ChartPanel panel = new ChartPanel(chart);
        panel.setMouseWheelEnabled(false);
        panel.setPopupMenu(null);
        return panel;
    }

    private void updateChartWindow(long nowMs) {
        long startMs = ExportStats.getExportStartRequestedAtMs();
        if (startMs <= 0) {
            startMs = firstSampleAtMs > 0 ? firstSampleAtMs : nowMs;
        }
        if (startMs > nowMs) {
            startMs = nowMs;
        }
        long minMs = (nowMs - startMs) < CHART_WINDOW_MAX_MS ? startMs : (nowMs - CHART_WINDOW_MAX_MS);
        updateDomainRange(docsChart, minMs, nowMs);
        updateDomainRange(kibChart, minMs, nowMs);
    }

    private static void updateDomainRange(JFreeChart chart, long minMs, long maxMs) {
        if (maxMs <= minMs) {
            maxMs = minMs + 1;
        }
        XYPlot plot = chart.getXYPlot();
        if (plot.getDomainAxis() instanceof DateAxis axis) {
            axis.setAutoRange(false);
            axis.setRange(new Date(minMs), new Date(maxMs));
        }
    }

    /**
     * Starts periodic refresh while this panel is in the display hierarchy.
     *
     * <p>Burp may remove/add tab content on tab switches. Keeping timer lifecycle tied to
     * add/remove prevents unnecessary refresh work while the panel is not visible.</p>
     */
    @Override
    public void addNotify() {
        super.addNotify();
        if (!refreshTimer.isRunning()) {
            refreshTimer.start();
        }
        if (isShowing()) {
            refreshVisibleStats();
        }
    }

    /**
     * Stops periodic refresh when panel is removed from the display hierarchy.
     */
    @Override
    public void removeNotify() {
        if (refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
        super.removeNotify();
    }

    static String buildStatsText() {
        StringBuilder sb = new StringBuilder();

        // Export state
        String osUrl = RuntimeConfig.openSearchUrl();
        boolean urlSet = osUrl != null && !osUrl.isBlank();
        boolean exportRunning = RuntimeConfig.isExportRunning();
        sb.append("Export state\n");
        sb.append("  export running: ").append(exportRunning ? "yes" : "no").append("\n");
        sb.append("  OpenSearch URL set: ").append(urlSet ? "yes" : "no").append("\n");
        sb.append("  current batch size: ").append(BatchSizeController.getInstance().getCurrentBatchSize()).append("\n");
        int trafficQueueSize = ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSize();
        long trafficQueueDrops = ExportStats.getTrafficQueueDrops();
        sb.append("  traffic queue: size=").append(trafficQueueSize).append(" drops=").append(trafficQueueDrops).append("\n");
        sb.append("  null tool/source hits: ").append(ExportStats.getTrafficToolSourceFallbacks()).append("\n");
        double throughput = ExportStats.getThroughputDocsPerSecLast60s();
        sb.append("  throughput (last 60s): ").append(String.format("%.1f", throughput)).append(" docs/s\n\n");

        // Efficiency metrics (startup and proxy-history backfill)
        sb.append("Efficiency\n");
        long startToFirstTrafficMs = ExportStats.getStartToFirstTrafficMs();
        if (startToFirstTrafficMs >= 0) {
            sb.append("  start -> first traffic push (ms): ").append(startToFirstTrafficMs).append("\n");
        } else {
            long startRequestedAt = ExportStats.getExportStartRequestedAtMs();
            if (startRequestedAt > 0) {
                sb.append("  start -> first traffic push (ms): pending\n");
            } else {
                sb.append("  start -> first traffic push (ms): n/a\n");
            }
        }
        ExportStats.ProxyHistorySnapshotStats proxySnapshot = ExportStats.getLastProxyHistorySnapshot();
        if (proxySnapshot != null) {
            sb.append("  proxy-history last snapshot: attempted=").append(proxySnapshot.attempted())
                    .append(" success=").append(proxySnapshot.success())
                    .append(" durationMs=").append(proxySnapshot.durationMs())
                    .append(" docs/s=").append(String.format("%.1f", proxySnapshot.docsPerSecond()))
                    .append(" finalChunkTarget=").append(proxySnapshot.finalChunkTarget())
                    .append("\n");
            sb.append("  proxy-history recorded at: ")
                    .append(Instant.ofEpochMilli(proxySnapshot.recordedAtMs()))
                    .append("\n");
        } else {
            sb.append("  proxy-history last snapshot: n/a\n");
        }
        sb.append("\n");

        // Session totals
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();
        sb.append("Session totals (this session)\n");
        sb.append("  total docs pushed: ").append(totalSuccess).append("\n");
        sb.append("  total failures: ").append(totalFailure).append("\n\n");

        // Traffic by source
        sb.append("Traffic by source\n");
        sb.append(String.format("  %-22s %-12s %-10s%n", "Source", "Docs pushed", "Failures"));
        sb.append("  ").append("-".repeat(22)).append(" ").append("-".repeat(12)).append(" ").append("-".repeat(10)).append("\n");
        long sourceTotalSuccess = 0;
        long sourceTotalFailure = 0;
        for (String sourceKey : ExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            long sourceSuccess = resolveSourceSuccess(sourceKey);
            long sourceFailure = resolveSourceFailure(sourceKey);
            sourceTotalSuccess += sourceSuccess;
            sourceTotalFailure += sourceFailure;
            sb.append(String.format("  %-22s %-12d %-10d%n", sourceKey.toLowerCase(Locale.ROOT), sourceSuccess, sourceFailure));
        }
        sb.append(String.format("  %-22s %-12d %-10d%n%n", "total", sourceTotalSuccess, sourceTotalFailure));

        // By index (table)
        sb.append("By index\n");
        sb.append(String.format("  %-10s %-12s %-8s %-8s %-10s %-14s  %s%n",
                "Index", "Docs pushed", "Queued", "Rty drop", "Failures", "Last push (ms)", "Last error"));
        sb.append("  ").append("-".repeat(10)).append(" ").append("-".repeat(12)).append(" ").append("-".repeat(8)).append(" ").append("-".repeat(8)).append(" ").append("-".repeat(10)).append(" ").append("-".repeat(14)).append("  ").append("-".repeat(ERROR_COL_MAX)).append("\n");
        for (String indexKey : ExportStats.getIndexKeys()) {
            long success = ExportStats.getSuccessCount(indexKey);
            int queued = ExportStats.getQueueSize(indexKey);
            long retryDrops = ExportStats.getRetryQueueDrops(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            long lastPushMs = ExportStats.getLastPushDurationMs(indexKey);
            String lastError = ExportStats.getLastError(indexKey);
            String lastPushStr = lastPushMs >= 0 ? String.valueOf(lastPushMs) : "-";
            String errStr = lastError != null ? truncateForColumn(lastError, ERROR_COL_MAX) : "-";
            sb.append(String.format("  %-10s %-12d %-8d %-8d %-10d %-14s  %s%n",
                    indexKey, success, queued, retryDrops, failure, lastPushStr, errStr));
        }
        sb.append("\n");

        // JVM stats: process total, then our extension (threads by name), then Burp + other (derived)
        Runtime rt = Runtime.getRuntime();
        long maxMb = rt.maxMemory() / MEGABYTE;
        long totalMb = rt.totalMemory() / MEGABYTE;
        long freeMb = rt.freeMemory() / MEGABYTE;
        long usedMb = totalMb - freeMb;

        long nonHeapUsedMb = -1;
        long nonHeapMaxMb = -1;
        int processThreadCount = -1;
        int ourExtensionThreadCount = -1;
        long uptimeSec = -1;
        long gcCount = -1;
        long gcTimeSec = -1;
        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            MemoryUsage nonHeap = memoryBean.getNonHeapMemoryUsage();
            if (nonHeap != null && nonHeap.getUsed() >= 0) {
                nonHeapUsedMb = nonHeap.getUsed() / MEGABYTE;
                nonHeapMaxMb = nonHeap.getMax() >= 0 ? nonHeap.getMax() / MEGABYTE : -1;
            }
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            processThreadCount = threadBean.getThreadCount();
            ourExtensionThreadCount = countOurExtensionThreads(threadBean);
            uptimeSec = ManagementFactory.getRuntimeMXBean().getUptime() / 1000;
            gcCount = ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionCount() >= 0 ? gc.getCollectionCount() : 0)
                    .sum();
            gcTimeSec = ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionTime() >= 0 ? gc.getCollectionTime() : 0)
                    .sum() / 1000;
        } catch (Exception ignored) {
            // JMX may be restricted
        }

        // Process total (Burp + all extensions; single JVM)
        sb.append("Process total (Burp + all extensions)\n");
        sb.append("  heap (MB): used=").append(usedMb).append(" max=").append(maxMb).append(" free=").append(freeMb).append("\n");
        if (nonHeapUsedMb >= 0) {
            sb.append("  non-heap (MB): used=").append(nonHeapUsedMb).append(" max=");
            if (nonHeapMaxMb >= 0) sb.append(nonHeapMaxMb); else sb.append("n/a");
            sb.append("  [metaspace, code cache]\n");
        }
        if (processThreadCount >= 0) {
            sb.append("  thread count: ").append(processThreadCount).append("\n");
        }
        if (uptimeSec >= 0) {
            sb.append("  uptime (s): ").append(uptimeSec).append("\n");
        }
        if (gcCount >= 0) {
            sb.append("  GC collections: ").append(gcCount).append("  total time (s): ").append(gcTimeSec).append("\n");
        }
        sb.append("\n");

        // Our extension (threads by name; memory n/a)
        sb.append("Our extension (attackframework-burp-exporter)\n");
        if (ourExtensionThreadCount >= 0) {
            sb.append("  threads (by name): ").append(ourExtensionThreadCount).append("\n");
        }
        sb.append("  memory: n/a (JVM does not expose per-extension heap)\n");
        sb.append("  activity: see Session totals and By index above.\n");
        sb.append("\n");

        // Burp + other extensions (derived thread count; memory n/a)
        sb.append("Burp + other extensions\n");
        if (processThreadCount >= 0 && ourExtensionThreadCount >= 0) {
            int otherThreads = Math.max(0, processThreadCount - ourExtensionThreadCount);
            sb.append("  threads (approx): ").append(otherThreads).append("  (process total minus our threads)\n");
        }
        sb.append("  memory: n/a (shared process heap; not separable via JVM APIs).\n");

        return sb.toString();
    }

    /** Counts threads we create (by known name prefixes). Heuristic only. */
    private static int countOurExtensionThreads(ThreadMXBean threadBean) {
        long[] ids = threadBean.getAllThreadIds();
        int count = 0;
        for (long id : ids) {
            var info = threadBean.getThreadInfo(id);
            if (info != null) {
                String name = info.getThreadName();
                if (name != null && (name.contains("attackframework") || name.contains("OpenSearchRetryDrain"))) {
                    count++;
                }
            }
        }
        return count;
    }

    /**
     * Resolves "Traffic by source" docs pushed count for a source key.
     *
     * <p>Most rows come from live captured tool-type counts. Proxy-history snapshot pushes are
     * recorded separately, so include those under the proxy_history row.</p>
     */
    private static long resolveSourceSuccess(String sourceKey) {
        long captured = ExportStats.getTrafficToolTypeCapturedCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            captured += ExportStats.getTrafficSourceSuccessCount("proxy_history_snapshot");
        }
        return captured;
    }

    /** Resolves "Traffic by source" failure count for a source key. */
    private static long resolveSourceFailure(String sourceKey) {
        if ("PROXY_HISTORY".equals(sourceKey)) {
            return ExportStats.getTrafficSourceFailureCount("proxy_history_snapshot");
        }
        return 0;
    }

    private static String truncateForColumn(String s, int maxLen) {
        if (s == null) return "-";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}
