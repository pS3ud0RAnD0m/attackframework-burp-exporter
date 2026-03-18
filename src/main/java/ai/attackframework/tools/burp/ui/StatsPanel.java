package ai.attackframework.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnit;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.chart.ui.RectangleInsets;
import org.jfree.chart.ui.VerticalAlignment;
import org.jfree.data.RangeType;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;
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
    private static final int ERROR_COL_MAX = 50;
    private static final int CHART_MAX_POINTS = 240;
    private static final int CHART_PANEL_HEIGHT = 460;
    private static final long CHART_WINDOW_MAX_MS = 60L * 60L * 1000L;
    private static final double DEFAULT_RATE_RANGE_MAX = 10.0;
    private static final String DOMAIN_TIME_PATTERN = "HH:mm:ss";
    private static final int DOMAIN_TARGET_LABELS = 14;
    private static final int[] DOMAIN_CANDIDATE_SECONDS = new int[] { 1, 2, 3, 5, 6, 10, 12, 15, 20, 30, 60, 120, 300 };
    private static final Font CHART_TITLE_FONT = new Font("SansSerif", Font.PLAIN, 14);
    private static final Font CHART_AXIS_LABEL_FONT = new Font("SansSerif", Font.PLAIN, 15);
    private static final Font CHART_TICK_FONT = new Font("SansSerif", Font.PLAIN, 11);
    private static final Font CHART_LEGEND_FONT = new Font("SansSerif", Font.PLAIN, 14);
    private static final Font CARD_KEY_FONT = new Font("SansSerif", Font.PLAIN, 13);
    private static final Font CARD_VALUE_FONT = new Font("SansSerif", Font.BOLD, 13);
    private static final float CHART_LINE_STROKE_WIDTH = 1.5f;
    private static final Color CHART_BG = new Color(38, 38, 38);
    private static final Color PLOT_BG = new Color(48, 48, 48);
    private static final Color TEXT_FG = new Color(235, 235, 235);
    private static final Color GRID_FG = new Color(95, 95, 95);
    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));
    private static final Color[] SERIES_COLORS = new Color[] {
            new Color(86, 156, 214),   // blue
            new Color(57, 255, 20),    // neon green
            new Color(220, 220, 170),  // yellow
            new Color(120, 70, 160),   // darker purple
            new Color(244, 71, 71)     // red
    };

    private final Timer refreshTimer;
    private final TimeSeriesCollection docsPerSecondDataset;
    private final TimeSeriesCollection kibPerSecondDataset;
    private final JFreeChart docsChart;
    private final JFreeChart kibChart;
    private final JLabel exportRunningValue;
    private final JLabel currentBatchSizeValue;
    private final JLabel trafficQueueValue;
    private final JLabel queueDropsValue;
    private final JLabel throughputValue;
    private final JLabel totalDocsPushedValue;
    private final JLabel totalFailuresValue;
    private final DefaultTableModel trafficBySourceModel;
    private final DefaultTableModel byIndexModel;
    private final JTable trafficBySourceTable;
    private final JTable byIndexTable;
    private final JPanel tablesRow;
    private final JPanel cardsRow;
    private final Map<String, TimeSeries> docsSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> kibSeriesByIndex = new HashMap<>();
    private final Map<String, Long> previousSuccessByIndex = new HashMap<>();
    private final Map<String, Long> previousBytesByIndex = new HashMap<>();
    private long lastLoggedToolSourceFallbacks = -1;
    private long firstSampleAtMs = -1;
    private long previousSampleAtMs = -1;

    /**
     * Creates the Stats panel and starts the refresh timer.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 900));

        docsPerSecondDataset = new TimeSeriesCollection();
        kibPerSecondDataset = new TimeSeriesCollection();
        docsChart = createRateChart(
                "Export - Docs/sec",
                "Docs per second",
                docsPerSecondDataset,
                false,
                false);
        kibChart = createRateChart(
                "Export - KiB/sec",
                "KiB per second",
                kibPerSecondDataset,
                false,
                true);

        JPanel chartsPanel = new JPanel(new BorderLayout(0, 4));
        JPanel chartGrid = new JPanel(new GridLayout(2, 1, 0, 12));
        chartGrid.add(createRateChartPanel(docsChart));
        chartGrid.add(createRateChartPanel(kibChart));
        chartsPanel.add(chartGrid, BorderLayout.CENTER);
        chartsPanel.add(createSharedLegendPanel(), BorderLayout.SOUTH);
        chartsPanel.setPreferredSize(new Dimension(1200, CHART_PANEL_HEIGHT));
        JPanel contentPanel = new JPanel(new BorderLayout(0, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));
        contentPanel.setBackground(UIManager.getColor("Panel.background"));
        contentPanel.add(chartsPanel, BorderLayout.NORTH);

        cardsRow = new JPanel(new GridLayout(1, 1, 10, 0));
        cardsRow.setOpaque(false);

        JLabel[] exportStateValues = addMetricCard(cardsRow, "Misc Stats", new String[] {
                "Export Running", "Current Batch Size", "Traffic Queue Size", "Queue Drops",
                "Throughput (Last 10s)", "Total Docs Pushed", "Total Failures"
        });
        exportRunningValue = exportStateValues[0];
        currentBatchSizeValue = exportStateValues[1];
        trafficQueueValue = exportStateValues[2];
        queueDropsValue = exportStateValues[3];
        throughputValue = exportStateValues[4];
        totalDocsPushedValue = exportStateValues[5];
        totalFailuresValue = exportStateValues[6];

        tablesRow = new JPanel(new GridLayout(1, 2, 10, 0));
        tablesRow.setOpaque(false);

        trafficBySourceModel = new DefaultTableModel(
                new String[] { "Source", "Docs Pushed", "Queued", "Retry Drops", "Failures", "Last Push (ms)", "Last Error" }, 0);
        trafficBySourceTable = createStatsTable(trafficBySourceModel);
        tablesRow.add(createTableCard("Traffic by Source", trafficBySourceTable));

        byIndexModel = new DefaultTableModel(
                new String[] { "Index", "Docs Pushed", "Queued", "Retry Drops", "Failures", "Last Push (ms)", "Last Error" }, 0);
        byIndexTable = createStatsTable(byIndexModel);
        if (byIndexTable.getRowSorter() != null) {
            byIndexTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.ASCENDING)));
        }
        tablesRow.add(createTableCard("Traffic by Index", byIndexTable));

        JPanel lowerPanel = new JPanel();
        lowerPanel.setLayout(new javax.swing.BoxLayout(lowerPanel, javax.swing.BoxLayout.Y_AXIS));
        lowerPanel.setOpaque(false);
        lowerPanel.add(tablesRow);
        lowerPanel.add(javax.swing.Box.createVerticalStrut(10));
        lowerPanel.add(cardsRow);
        contentPanel.add(lowerPanel, BorderLayout.CENTER);
        add(contentPanel, BorderLayout.CENTER);

        refreshTimer = new Timer(REFRESH_INTERVAL_MS, e -> refreshVisibleStats());
        refreshTimer.setRepeats(true);

        refreshVisibleStats();
        updateDashboardSectionSizing();
    }

    private void refreshVisibleStats() {
        sampleRateSeries();
        refreshDashboard();
    }

    private void refreshDashboard() {
        boolean exportRunning = RuntimeConfig.isExportRunning();
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();

        exportRunningValue.setText(exportRunning ? "Yes" : "No");
        currentBatchSizeValue.setText(formatWhole(BatchSizeController.getInstance().getCurrentBatchSize()));
        trafficQueueValue.setText(formatWhole(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSize()));
        queueDropsValue.setText(formatWhole(ExportStats.getTrafficQueueDrops()));
        throughputValue.setText(DECIMAL_ONE.format(ExportStats.getThroughputDocsPerSecLast10s()) + " docs/s");
        long fallbackHits = ExportStats.getTrafficToolSourceFallbacks();
        if (fallbackHits > 0 && fallbackHits != lastLoggedToolSourceFallbacks) {
            Logger.logError("Traffic tool/source fallback hits observed: " + fallbackHits);
            lastLoggedToolSourceFallbacks = fallbackHits;
        }

        totalDocsPushedValue.setText(formatWhole(totalSuccess));
        totalFailuresValue.setText(formatWhole(totalFailure));

        rebuildTrafficBySourceTable();
        rebuildByIndexTable();
        updateTablePreferredHeight(trafficBySourceTable);
        updateTablePreferredHeight(byIndexTable);
        updateDashboardSectionSizing();
        revalidate();
    }

    private void rebuildTrafficBySourceTable() {
        trafficBySourceModel.setRowCount(0);
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
            trafficBySourceModel.addRow(new Object[] {
                    formatKeyLabel(sourceKey),
                    sourceSuccess,
                    "-",
                    "-",
                    sourceFailure,
                    "-",
                    "-"
            });
        }
        trafficBySourceModel.addRow(new Object[] { "Total", sourceTotalSuccess, "-", "-", sourceTotalFailure, "-", "-" });
    }

    private void rebuildByIndexTable() {
        byIndexModel.setRowCount(0);
        for (String indexKey : ExportStats.getIndexKeys()) {
            long success = ExportStats.getSuccessCount(indexKey);
            int queued = ExportStats.getQueueSize(indexKey);
            long retryDrops = ExportStats.getRetryQueueDrops(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            long lastPushMs = ExportStats.getLastPushDurationMs(indexKey);
            String lastPushStr = lastPushMs >= 0 ? String.valueOf(lastPushMs) : "-";
            String lastError = ExportStats.getLastError(indexKey);
            String errStr = lastError != null ? truncateForColumn(lastError, ERROR_COL_MAX) : "-";
            byIndexModel.addRow(new Object[] {
                    formatKeyLabel(indexKey), success, queued, retryDrops, failure, lastPushStr, errStr
            });
        }
    }

    private static JPanel createTableCard(String title, JTable table) {
        JPanel card = new JPanel(new BorderLayout(0, 6));
        card.setBorder(BorderFactory.createTitledBorder(title));
        card.add(table.getTableHeader(), BorderLayout.NORTH);
        card.add(table, BorderLayout.CENTER);
        return card;
    }

    private static JTable createStatsTable(DefaultTableModel model) {
        model.setRowCount(0);
        JTable table = new JTable(model) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(22);
        DefaultTableCellRenderer leftAligned = new DefaultTableCellRenderer();
        leftAligned.setHorizontalAlignment(SwingConstants.LEFT);
        for (int columnIndex = 0; columnIndex < table.getColumnCount(); columnIndex++) {
            table.getColumnModel().getColumn(columnIndex).setCellRenderer(leftAligned);
        }
        updateTablePreferredHeight(table);
        return table;
    }

    private static JLabel[] addMetricCard(JPanel parent, String title, String[] keys) {
        JPanel card = new JPanel(new GridBagLayout());
        card.setBorder(BorderFactory.createTitledBorder(title));
        card.setPreferredSize(new Dimension(420, Math.max(180, keys.length * 22)));
        card.setMinimumSize(new Dimension(360, Math.max(160, keys.length * 20)));
        int maxKeyWidth = 0;
        for (String key : keys) {
            JLabel probe = new JLabel(key);
            probe.setFont(CARD_KEY_FONT);
            maxKeyWidth = Math.max(maxKeyWidth, probe.getPreferredSize().width);
        }
        JLabel[] values = new JLabel[keys.length];
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridy = 0;
        gbc.insets = new Insets(1, 0, 1, 8);
        gbc.anchor = GridBagConstraints.WEST;
        for (int i = 0; i < keys.length; i++) {
            JLabel keyLabel = new JLabel(keys[i]);
            keyLabel.setForeground(UIManager.getColor("Label.foreground"));
            keyLabel.setFont(CARD_KEY_FONT);
            keyLabel.setPreferredSize(new Dimension(maxKeyWidth, keyLabel.getPreferredSize().height));
            JLabel valueLabel = new JLabel("-");
            valueLabel.setHorizontalAlignment(SwingConstants.LEFT);
            valueLabel.setForeground(UIManager.getColor("Label.foreground"));
            valueLabel.setFont(CARD_VALUE_FONT);
            values[i] = valueLabel;
            gbc.gridx = 0;
            gbc.weightx = 0;
            card.add(keyLabel, gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            gbc.insets = new Insets(1, 0, 1, 0);
            card.add(valueLabel, gbc);
            gbc.gridy++;
            gbc.insets = new Insets(1, 0, 1, 8);
        }
        parent.add(card);
        return values;
    }

    private void updateDashboardSectionSizing() {
        int leftTableHeight = trafficBySourceTable.getPreferredSize().height
                + trafficBySourceTable.getTableHeader().getPreferredSize().height + 28;
        int rightTableHeight = byIndexTable.getPreferredSize().height
                + byIndexTable.getTableHeader().getPreferredSize().height + 28;
        int tablesHeight = Math.max(leftTableHeight, rightTableHeight);
        tablesRow.setPreferredSize(new Dimension(1200, tablesHeight));
        tablesRow.setMinimumSize(new Dimension(800, tablesHeight));

        int cardsHeight = 220;
        cardsRow.setPreferredSize(new Dimension(1200, cardsHeight));
        cardsRow.setMinimumSize(new Dimension(800, cardsHeight));
    }

    private static String formatWhole(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    private static void updateTablePreferredHeight(JTable table) {
        int rows = Math.max(1, table.getRowCount());
        int headerHeight = table.getTableHeader() != null ? table.getTableHeader().getPreferredSize().height : 24;
        int totalHeight = headerHeight + (rows * table.getRowHeight()) + 6;
        int preferredWidth = Math.max(700, table.getPreferredSize().width);
        table.setPreferredScrollableViewportSize(new Dimension(preferredWidth, totalHeight));
        table.setPreferredSize(new Dimension(preferredWidth, Math.max(1, totalHeight - headerHeight)));
    }

    private static String formatKeyLabel(String key) {
        if (key == null || key.isBlank()) {
            return "";
        }
        String[] parts = key.toLowerCase(Locale.ROOT).replace('_', ' ').split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
        }
        return sb.toString();
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
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            docsPerSecondDataset.addSeries(s);
            return s;
        });
        kibSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            kibPerSecondDataset.addSeries(s);
            return s;
        });
    }

    private static String displaySeriesLabel(String indexKey) {
        if (indexKey == null || indexKey.isBlank()) {
            return "";
        }
        return Character.toUpperCase(indexKey.charAt(0)) + indexKey.substring(1);
    }

    private static JFreeChart createRateChart(
            String title,
            String yLabel,
            TimeSeriesCollection dataset,
            boolean showLegend,
            boolean showDomainLabel) {
        JFreeChart chart = ChartFactory.createTimeSeriesChart(title, "Time", yLabel, dataset, showLegend, false, false);
        chart.setBackgroundPaint(CHART_BG);
        chart.setPadding(RectangleInsets.ZERO_INSETS);
        TextTitle titleNode = chart.getTitle();
        titleNode.setPaint(TEXT_FG);
        titleNode.setFont(CHART_TITLE_FONT);
        titleNode.setVerticalAlignment(VerticalAlignment.BOTTOM);
        // Keep title visually attached to the chart area.
        titleNode.setMargin(RectangleInsets.ZERO_INSETS);
        titleNode.setPadding(RectangleInsets.ZERO_INSETS);
        XYPlot plot = chart.getXYPlot();
        plot.setInsets(new RectangleInsets(1, 2, 2, 2));
        plot.setBackgroundPaint(PLOT_BG);
        plot.setDomainGridlinePaint(GRID_FG);
        plot.setRangeGridlinePaint(GRID_FG);
        plot.setDomainGridlinesVisible(true);
        plot.setRangeGridlinesVisible(true);
        ValueAxis domain = plot.getDomainAxis();
        ValueAxis range = plot.getRangeAxis();
        if (range instanceof NumberAxis numberAxis) {
            // Throughput charts are non-negative metrics; keep zero anchored at the bottom.
            numberAxis.setRangeType(RangeType.POSITIVE);
            numberAxis.setAutoRangeIncludesZero(true);
            numberAxis.setAutoRangeStickyZero(true);
            // Keep Y-axis labels/ticks as whole numbers for readability.
            numberAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        }
        if (domain != null) {
            domain.setLabelPaint(TEXT_FG);
            domain.setTickLabelPaint(TEXT_FG);
            domain.setLabelFont(CHART_AXIS_LABEL_FONT);
            domain.setTickLabelFont(CHART_TICK_FONT);
            domain.setTickLabelsVisible(true);
            if (!showDomainLabel) {
                domain.setLabel(null);
            }
            if (domain instanceof DateAxis dateAxis) {
                // Keep x-axis labels human-readable as local wall-clock time.
                dateAxis.setDateFormatOverride(new SimpleDateFormat(DOMAIN_TIME_PATTERN));
            }
        }
        if (range != null) {
            range.setLabelPaint(TEXT_FG);
            range.setTickLabelPaint(TEXT_FG);
            range.setLabelFont(CHART_AXIS_LABEL_FONT);
            range.setTickLabelFont(CHART_TICK_FONT);
        }
        XYLineAndShapeRenderer renderer = (XYLineAndShapeRenderer) plot.getRenderer();
        renderer.setDefaultShapesVisible(false);
        renderer.setDefaultStroke(new BasicStroke(CHART_LINE_STROKE_WIDTH));
        for (int i = 0; i < SERIES_COLORS.length; i++) {
            renderer.setSeriesPaint(i, SERIES_COLORS[i]);
            renderer.setSeriesStroke(i, new BasicStroke(CHART_LINE_STROKE_WIDTH));
        }
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(CHART_BG);
            chart.getLegend().setItemPaint(TEXT_FG);
            chart.getLegend().setItemFont(CHART_LEGEND_FONT);
        }
        return chart;
    }

    private static ChartPanel createRateChartPanel(JFreeChart chart) {
        ChartPanel panel = new ChartPanel(chart);
        panel.setMouseWheelEnabled(false);
        panel.setPopupMenu(null);
        return panel;
    }

    private static JPanel createSharedLegendPanel() {
        JPanel legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        legendPanel.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 0));
        legendPanel.setOpaque(false);
        String[] labels = { "Traffic", "Tool", "Settings", "Sitemap", "Findings" };
        for (int i = 0; i < labels.length; i++) {
            JLabel legendItem = new JLabel("\u2014 " + labels[i], SwingConstants.LEFT);
            legendItem.setForeground(SERIES_COLORS[i]);
            legendItem.setFont(CHART_TICK_FONT);
            legendPanel.add(legendItem);
        }
        return legendPanel;
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
        applyReasonableDefaultRange(docsChart, docsPerSecondDataset, DEFAULT_RATE_RANGE_MAX);
        applyReasonableDefaultRange(kibChart, kibPerSecondDataset, DEFAULT_RATE_RANGE_MAX);
    }

    private static void updateDomainRange(JFreeChart chart, long minMs, long maxMs) {
        if (maxMs <= minMs) {
            maxMs = minMs + 1;
        }
        XYPlot plot = chart.getXYPlot();
        if (plot.getDomainAxis() instanceof DateAxis axis) {
            axis.setAutoRange(false);
            axis.setRange(new Date(minMs), new Date(maxMs));
            configureDomainTickUnit(axis, minMs, maxMs);
        }
    }

    /**
     * Chooses a readable date tick unit from a small "nice" set to keep label count bounded.
     *
     * <p>Without this, date labels can become too dense over long sessions and increase render
     * overhead on repeated refresh. This keeps the chart adaptive while avoiding label crowding.</p>
     */
    private static void configureDomainTickUnit(DateAxis axis, long minMs, long maxMs) {
        long spanMs = Math.max(1L, maxMs - minMs);
        double targetStepSec = Math.max(1.0, (spanMs / 1000.0) / DOMAIN_TARGET_LABELS);
        int chosenSec = DOMAIN_CANDIDATE_SECONDS[DOMAIN_CANDIDATE_SECONDS.length - 1];
        for (int candidate : DOMAIN_CANDIDATE_SECONDS) {
            if (candidate >= targetStepSec) {
                chosenSec = candidate;
                break;
            }
        }
        axis.setTickUnit(new DateTickUnit(DateTickUnitType.SECOND, chosenSec));
    }

    /**
     * Keeps a sane startup Y-axis range while charts have no positive throughput yet.
     *
     * <p>With empty/zero-only data, chart auto-range can pick confusing scientific-notation bounds
     * near zero. This fallback shows {@code 0..defaultMax} until positive values appear, then
     * returns to adaptive auto-range.</p>
     */
    private static void applyReasonableDefaultRange(
            JFreeChart chart, TimeSeriesCollection dataset, double defaultMax) {
        XYPlot plot = chart.getXYPlot();
        ValueAxis rangeAxis = plot.getRangeAxis();
        if (!(rangeAxis instanceof NumberAxis numberAxis)) {
            return;
        }
        if (hasAnyPositiveSample(dataset)) {
            numberAxis.setAutoRange(true);
            return;
        }
        numberAxis.setAutoRange(false);
        numberAxis.setRange(0.0, defaultMax);
    }

    /** Returns {@code true} when any series currently contains a value &gt; 0. */
    private static boolean hasAnyPositiveSample(TimeSeriesCollection dataset) {
        for (int seriesIndex = 0; seriesIndex < dataset.getSeriesCount(); seriesIndex++) {
            TimeSeries series = dataset.getSeries(seriesIndex);
            int items = series.getItemCount();
            for (int itemIndex = 0; itemIndex < items; itemIndex++) {
                Number value = series.getValue(itemIndex);
                if (value != null && value.doubleValue() > 0.0) {
                    return true;
                }
            }
        }
        return false;
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
        boolean exportRunning = RuntimeConfig.isExportRunning();
        sb.append("Export state\n");
        sb.append("  export running: ").append(exportRunning ? "yes" : "no").append("\n");
        sb.append("  current batch size: ").append(BatchSizeController.getInstance().getCurrentBatchSize()).append("\n");
        int trafficQueueSize = ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSize();
        long trafficQueueDrops = ExportStats.getTrafficQueueDrops();
        sb.append("  traffic queue: size=").append(trafficQueueSize).append(" drops=").append(trafficQueueDrops).append("\n");
        sb.append("  null tool/source hits: ").append(ExportStats.getTrafficToolSourceFallbacks()).append("\n");
        double throughput = ExportStats.getThroughputDocsPerSecLast10s();
        sb.append("  throughput (last 10s): ").append(String.format("%.1f", throughput)).append(" docs/s\n\n");

        // Efficiency metrics (startup and proxy-history backfill)
        sb.append("Efficiency\n");
        long startToFirstTrafficMs = ExportStats.getStartToFirstTrafficMs();
        if (startToFirstTrafficMs >= 0) {
            sb.append("  start click -> first successful traffic doc acknowledged (ms): ")
                    .append(startToFirstTrafficMs).append("\n");
        } else {
            long startRequestedAt = ExportStats.getExportStartRequestedAtMs();
            if (startRequestedAt > 0) {
                sb.append("  start click -> first successful traffic doc acknowledged (ms): pending\n");
            } else {
                sb.append("  start click -> first successful traffic doc acknowledged (ms): n/a\n");
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

        return sb.toString();
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
