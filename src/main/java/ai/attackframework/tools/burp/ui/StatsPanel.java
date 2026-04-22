package ai.attackframework.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.Paint;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

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
import org.jfree.chart.renderer.xy.XYSplineRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.chart.ui.RectangleInsets;
import org.jfree.chart.ui.VerticalAlignment;
import org.jfree.data.RangeType;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.Rectangle2D;

import ai.attackframework.tools.burp.ui.text.Tooltips;
import ai.attackframework.tools.burp.sinks.TrafficRouteBucket;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.BatchSizeController;

/**
 * Panel that displays live export charts and dashboard metrics.
 *
 * <p>Updates every few seconds via a Swing {@link Timer}. The panel shows rolling throughput
 * charts, per-index and per-source traffic tables, and a compact "Misc Stats" card with the
 * current export state. Sink-specific chart/table sections are shown only when that destination is
 * selected at runtime. Caller must construct on the EDT.</p>
 */
public class StatsPanel extends JPanel {

    private static final String[] CHART_STYLE_NAMES = { "Simple", "Smooth", "Accessible" };

    private static final int PANEL_BASE_WIDTH = 1200;
    private static final int PANEL_BASE_HEIGHT = 900;
    private static final int CONTENT_VERTICAL_PADDING = 56;
    private static final int REFRESH_INTERVAL_MS = 3000;
    private static final int ERROR_COL_MAX = 50;
    private static final long CHART_WINDOW_MAX_MS = 60L * 60L * 1000L;
    private static final int CHART_MAX_POINTS = (int) (CHART_WINDOW_MAX_MS / REFRESH_INTERVAL_MS) + 5;
    private static final int CHART_PANEL_HEIGHT = 360;
    private static final double DEFAULT_RATE_RANGE_MAX = 10.0;
    private static final String DOMAIN_TIME_PATTERN = "HH:mm:ss";
    private static final int DOMAIN_TARGET_LABELS = 14;
    private static final int[] DOMAIN_CANDIDATE_SECONDS = new int[] { 1, 2, 3, 5, 6, 10, 12, 15, 20, 30, 60, 120, 300 };
    private static final Font CHART_TITLE_FONT = uiFont(Font.PLAIN, 14f);
    private static final Font CHART_AXIS_LABEL_FONT = uiFont(Font.PLAIN, 15f);
    private static final Font CHART_TICK_FONT = uiFont(Font.PLAIN, 11f);
    private static final Font CHART_LEGEND_FONT = uiFont(Font.PLAIN, 15f);
    private static final Font CARD_KEY_FONT = uiFont(Font.PLAIN, 12f);
    private static final Font CARD_VALUE_FONT = uiFont(Font.PLAIN, 12f);
    private static final float CHART_LINE_STROKE_WIDTH = 1.5f;
    private static final Color TEXT_FG = uiColor("Label.foreground", new Color(235, 235, 235));
    private static final int LEGEND_ICON_WIDTH = 28;
    private static final int LEGEND_ICON_HEIGHT = 14;
    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));
    private static final SeriesStyle[] SERIES_STYLES = new SeriesStyle[] {
            new SeriesStyle(
                    "Traffic",
                    new Color(57, 255, 20),
                    new Color(46, 140, 54),
                    new float[] { 8f, 5f },
                    squareMarker(6f),
                    true),
            new SeriesStyle(
                    "Exporter",
                    new Color(174, 126, 255),
                    new Color(112, 74, 176),
                    new float[] { 8f, 4f, 1.5f, 4f },
                    diamondMarker(7f),
                    true),
            new SeriesStyle(
                    "Settings",
                    new Color(86, 156, 214),
                    new Color(41, 98, 179),
                    null,
                    circleMarker(6f),
                    true),
            new SeriesStyle(
                    "Sitemap",
                    new Color(255, 210, 92),
                    new Color(196, 138, 0),
                    new float[] { 1.5f, 4f },
                    triangleMarker(7f),
                    true),
            new SeriesStyle(
                    "Findings",
                    new Color(244, 71, 71),
                    new Color(191, 52, 52),
                    new float[] { 12f, 6f },
                    crossMarker(7f),
                    false)
    };

    private record SeriesStyle(
            String label,
            Color darkColor,
            Color lightColor,
            float[] dashPattern,
            Shape markerShape,
            boolean markerFilled) {

        private Color paint() {
            return isDarkTheme() ? darkColor : lightColor;
        }

        private BasicStroke stroke(float width) {
            if (dashPattern == null || dashPattern.length == 0) {
                return new BasicStroke(width, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
            }
            return new BasicStroke(
                    width,
                    BasicStroke.CAP_ROUND,
                    BasicStroke.JOIN_ROUND,
                    1f,
                    dashPattern,
                    0f);
        }
    }

    private final class LegendSampleIcon implements Icon {

        private final int seriesIndex;

        private LegendSampleIcon(int seriesIndex) {
            this.seriesIndex = seriesIndex;
        }

        @Override
        public void paintIcon(java.awt.Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int centerY = y + (LEGEND_ICON_HEIGHT / 2);
                int startX = x + 1;
                int endX = x + LEGEND_ICON_WIDTH - 2;
                g2.setPaint(legendPaint(seriesIndex, y, y + LEGEND_ICON_HEIGHT));
                g2.setStroke(seriesStroke(seriesIndex));
                g2.draw(new Line2D.Float(startX, centerY, endX, centerY));

                g2.translate(x + (LEGEND_ICON_WIDTH / 2.0), centerY);
                g2.setStroke(new BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                Shape marker = seriesMarkerShape(seriesIndex);
                if (seriesShapesVisible(seriesIndex) && marker != null) {
                    g2.setPaint(seriesSolidColor(seriesIndex));
                    if (seriesShapesFilled(seriesIndex)) {
                        g2.fill(marker);
                    }
                    g2.draw(marker);
                }
            } finally {
                g2.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return LEGEND_ICON_WIDTH;
        }

        @Override
        public int getIconHeight() {
            return LEGEND_ICON_HEIGHT;
        }
    }

    private final Timer refreshTimer;
    private final TimeSeriesCollection docsPerSecondDataset;
    private final TimeSeriesCollection kibPerSecondDataset;
    private final TimeSeriesCollection fileDocsPerSecondDataset;
    private final TimeSeriesCollection fileKibPerSecondDataset;
    private final JFreeChart docsChart;
    private final JFreeChart kibChart;
    private final JFreeChart fileDocsChart;
    private final JFreeChart fileKibChart;
    private final JPanel chartsPanel;
    private final JPanel chartSectionsPanel;
    private final JPanel fileChartsSectionPanel;
    private final JPanel openSearchChartsSectionPanel;
    private final JPanel openSearchDocsChartPanel;
    private final JPanel openSearchKibChartPanel;
    private final JPanel fileDocsChartPanel;
    private final JPanel fileKibChartPanel;
    private final JPanel sharedLegendPanel;
    private final JButton chartStyleButton;
    private final JLabel exportRunningValue;
    private final JLabel currentBatchSizeValue;
    private final JLabel trafficQueueValue;
    private final JLabel queueDropsValue;
    private final JLabel repeaterMetadataSourcesValue;
    private final JLabel spillQueueDocsValue;
    private final JLabel spillQueueMibValue;
    private final JLabel spillOldestAgeValue;
    private final JLabel spillFlowValue;
    private final JLabel dropReasonValue;
    private final JLabel spillRecoveredValue;
    private final JLabel spillDirectoryValue;
    private final JLabel throughputValue;
    private final JLabel totalExportedValue;
    private final JLabel totalDocsPushedValue;
    private final JLabel totalFailuresValue;
    private final JLabel fileTotalExportedValue;
    private final JLabel fileTotalDocsPushedValue;
    private final JLabel fileTotalFailuresValue;
    private final DefaultTableModel trafficBySourceModel;
    private final DefaultTableModel byIndexModel;
    private final DefaultTableModel fileTrafficBySourceModel;
    private final DefaultTableModel fileByIndexModel;
    private final JTable trafficBySourceTable;
    private final JTable byIndexTable;
    private final JTable fileTrafficBySourceTable;
    private final JTable fileByIndexTable;
    private final JPanel tablesRow;
    private final JPanel fileTablesRow;
    private final JPanel cardsRow;
    private final JPanel lowerPanel;
    private final JPanel miscStatsCard;
    private final Map<String, List<Component>> miscSectionComponents;
    private final Map<String, TimeSeries> docsSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> kibSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> fileDocsSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> fileKibSeriesByIndex = new HashMap<>();
    private final Map<String, Long> previousSuccessByIndex = new HashMap<>();
    private final Map<String, Long> previousBytesByIndex = new HashMap<>();
    private final Map<String, Long> previousFileSuccessByIndex = new HashMap<>();
    private final Map<String, Long> previousFileBytesByIndex = new HashMap<>();
    private long lastLoggedToolSourceFallbacks = -1;
    private long firstSampleAtMs = -1;
    private long previousSampleAtMs = -1;
    private int chartStyleIndex = 0;
    private final transient RuntimeConfig.StateListener runtimeStateListener;

    /**
     * Creates the Stats panel and starts the refresh timer.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(PANEL_BASE_WIDTH, PANEL_BASE_HEIGHT));

        docsPerSecondDataset = new TimeSeriesCollection();
        kibPerSecondDataset = new TimeSeriesCollection();
        fileDocsPerSecondDataset = new TimeSeriesCollection();
        fileKibPerSecondDataset = new TimeSeriesCollection();
        docsChart = createRateChart(
                "OpenSearch Export - Docs/sec",
                "Docs per second",
                docsPerSecondDataset,
                false,
                false);
        kibChart = createRateChart(
                "OpenSearch Export - KiB/sec",
                "KiB per second",
                kibPerSecondDataset,
                false,
                true);
        fileDocsChart = createRateChart(
                "File Export - Docs/sec",
                "Docs per second",
                fileDocsPerSecondDataset,
                false,
                false);
        fileKibChart = createRateChart(
                "File Export - KiB/sec",
                "KiB per second",
                fileKibPerSecondDataset,
                false,
                true);

        chartsPanel = new JPanel(new BorderLayout(0, 4));
        chartSectionsPanel = new JPanel();
        chartSectionsPanel.setLayout(new javax.swing.BoxLayout(chartSectionsPanel, javax.swing.BoxLayout.Y_AXIS));
        chartSectionsPanel.setOpaque(false);
        fileDocsChartPanel = createRateChartPanel(fileDocsChart);
        fileKibChartPanel = createRateChartPanel(fileKibChart);
        openSearchDocsChartPanel = createRateChartPanel(docsChart);
        openSearchKibChartPanel = createRateChartPanel(kibChart);
        fileChartsSectionPanel = buildChartSection(fileDocsChartPanel, fileKibChartPanel, 12);
        openSearchChartsSectionPanel = buildChartSection(openSearchDocsChartPanel, openSearchKibChartPanel, 0);
        chartSectionsPanel.add(fileChartsSectionPanel);
        chartSectionsPanel.add(openSearchChartsSectionPanel);
        chartsPanel.add(chartSectionsPanel, BorderLayout.CENTER);
        sharedLegendPanel = createSharedLegendPanel();
        chartStyleButton = createChartStyleButton();
        fileChartsSectionPanel.add(sharedLegendPanel, 0);
        runtimeStateListener = this::onRuntimeStateChanged;
        chartStyleIndex = Math.clamp(RuntimeConfig.statsChartStyle(), 1, CHART_STYLE_NAMES.length) - 1;
        applyChartStyles();
        refreshSharedLegendPanel();
        JPanel contentPanel = new JPanel(new BorderLayout(0, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));
        contentPanel.setBackground(UIManager.getColor("Panel.background"));
        contentPanel.add(chartsPanel, BorderLayout.NORTH);

        cardsRow = new JPanel(new GridLayout(1, 1, 10, 0));
        cardsRow.setOpaque(false);

        MetricCardState miscState = addGroupedMetricCard(cardsRow, "Misc Stats", List.of(
                new MetricSection("Global", new String[] {
                        "Export Running", "Current Batch Size", "Traffic Queue Size", "Queue Drops",
                        "Repeater Metadata Sources"
                }),
                new MetricSection("OpenSearch", new String[] {
                        "Spill Queue Docs", "Spill Queue MiB", "Spill Oldest Age (s)", "Spill Enq/Deq/Drops",
                        "Drop Reasons (Spill/Queue/Requeue/Retention)", "Spill Recovered (Startup)", "Spill Directory",
                        "OpenSearch Throughput (Last 10s)", "OpenSearch Total Size Exported",
                        "OpenSearch Total Docs Exported", "OpenSearch Total Failures"
                }),
                new MetricSection("Files", new String[] {
                        "File Total Size Exported", "File Total Docs Exported", "File Total Failures"
                })
        ));
        miscStatsCard = miscState.card();
        miscSectionComponents = miscState.sections();
        Map<String, JLabel> miscValues = miscState.values();
        exportRunningValue = miscValues.get("Export Running");
        currentBatchSizeValue = miscValues.get("Current Batch Size");
        trafficQueueValue = miscValues.get("Traffic Queue Size");
        queueDropsValue = miscValues.get("Queue Drops");
        repeaterMetadataSourcesValue = miscValues.get("Repeater Metadata Sources");
        spillQueueDocsValue = miscValues.get("Spill Queue Docs");
        spillQueueMibValue = miscValues.get("Spill Queue MiB");
        spillOldestAgeValue = miscValues.get("Spill Oldest Age (s)");
        spillFlowValue = miscValues.get("Spill Enq/Deq/Drops");
        dropReasonValue = miscValues.get("Drop Reasons (Spill/Queue/Requeue/Retention)");
        spillRecoveredValue = miscValues.get("Spill Recovered (Startup)");
        spillDirectoryValue = miscValues.get("Spill Directory");
        throughputValue = miscValues.get("OpenSearch Throughput (Last 10s)");
        totalExportedValue = miscValues.get("OpenSearch Total Size Exported");
        totalDocsPushedValue = miscValues.get("OpenSearch Total Docs Exported");
        totalFailuresValue = miscValues.get("OpenSearch Total Failures");
        fileTotalExportedValue = miscValues.get("File Total Size Exported");
        fileTotalDocsPushedValue = miscValues.get("File Total Docs Exported");
        fileTotalFailuresValue = miscValues.get("File Total Failures");

        tablesRow = new JPanel(new GridLayout(1, 2, 10, 0));
        tablesRow.setOpaque(false);
        fileTablesRow = new JPanel(new GridLayout(1, 2, 10, 0));
        fileTablesRow.setOpaque(false);

        trafficBySourceModel = new DefaultTableModel(
                new String[] { "Source", "Docs Exported", "Queued", "Retry Drops", "Failures", "Last Push (ms)", "Last Error" }, 0);
        trafficBySourceTable = createStatsTable(trafficBySourceModel);

        byIndexModel = new DefaultTableModel(
                new String[] { "Index", "Docs Exported", "Queued", "Retry Drops", "Failures", "Last Push (ms)", "Last Error" }, 0);
        byIndexTable = createStatsTable(byIndexModel);
        fileTrafficBySourceModel = new DefaultTableModel(
                new String[] { "Source", "Docs Exported", "Queued", "Retry Drops", "Failures", "Last Push (ms)", "Last Error" }, 0);
        fileTrafficBySourceTable = createStatsTable(fileTrafficBySourceModel);
        fileByIndexModel = new DefaultTableModel(
                new String[] { "Index", "Docs Exported", "Queued", "Retry Drops", "Failures", "Last Push (ms)", "Last Error" }, 0);
        fileByIndexTable = createStatsTable(fileByIndexModel);
        tablesRow.add(createTableCard("OpenSearch Index Counts", byIndexTable));
        tablesRow.add(createTableCard("OpenSearch Traffic Counts", trafficBySourceTable));
        fileTablesRow.add(createTableCard("File Index Counts", fileByIndexTable));
        fileTablesRow.add(createTableCard("File Traffic Counts", fileTrafficBySourceTable));

        lowerPanel = new JPanel();
        lowerPanel.setLayout(new javax.swing.BoxLayout(lowerPanel, javax.swing.BoxLayout.Y_AXIS));
        lowerPanel.setOpaque(false);
        lowerPanel.add(fileTablesRow);
        lowerPanel.add(javax.swing.Box.createVerticalStrut(10));
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
        exportRunningValue.setForeground(exportRunning ? SERIES_STYLES[0].paint() : SERIES_STYLES[4].paint());
        exportRunningValue.setFont(CARD_VALUE_FONT.deriveFont(Font.BOLD));
        currentBatchSizeValue.setText(formatWhole(BatchSizeController.getInstance().getCurrentBatchSize()));
        trafficQueueValue.setText(formatWhole(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSize()));
        queueDropsValue.setText(formatWhole(ExportStats.getTrafficQueueDrops()));
        repeaterMetadataSourcesValue.setText(ExportStats.describeRepeaterMetadataSourceCounts());
        spillQueueDocsValue.setText(formatWhole(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSpillSize()));
        long spillBytes = ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSpillBytes();
        spillQueueMibValue.setText(DECIMAL_ONE.format(spillBytes / (1024.0 * 1024.0)));
        spillOldestAgeValue.setText(
                DECIMAL_ONE.format(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSpillOldestAgeMs() / 1000.0));
        spillFlowValue.setText(
                formatWhole(ExportStats.getTrafficSpillEnqueued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDequeued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDrops()));
        dropReasonValue.setText(
                formatWhole(ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest")) + " / "
                        + formatWhole(ExportStats.getTrafficDropReasonCount("queue_contention_drop")) + " / "
                        + formatWhole(ExportStats.getTrafficDropReasonCount("spill_requeue_failed_drop")) + " / "
                        + formatWhole(ExportStats.getTrafficSpillExpiredPruned()));
        spillRecoveredValue.setText(
                formatWhole(ExportStats.getTrafficSpillRecovered()) + " (live: "
                        + formatWhole(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getRecoveredSpillCount()) + ")");
        spillDirectoryValue.setText(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getSpillDirectoryPath());
        throughputValue.setText(DECIMAL_ONE.format(ExportStats.getThroughputDocsPerSecLast10s()) + " docs/s");
        totalExportedValue.setText(formatHumanReadableBytes(ExportStats.getTotalExportedBytes()));
        fileTotalExportedValue.setText(formatHumanReadableBytes(FileExportStats.getTotalExportedBytes()));
        long fallbackHits = ExportStats.getTrafficToolSourceFallbacks();
        if (fallbackHits > 0 && fallbackHits != lastLoggedToolSourceFallbacks) {
            Logger.logError("Traffic tool/source fallback hits observed: " + fallbackHits);
            lastLoggedToolSourceFallbacks = fallbackHits;
        }

        totalDocsPushedValue.setText(formatWhole(totalSuccess));
        totalFailuresValue.setText(formatWhole(totalFailure));
        fileTotalDocsPushedValue.setText(formatWhole(FileExportStats.getTotalSuccessCount()));
        fileTotalFailuresValue.setText(formatWhole(FileExportStats.getTotalFailureCount()));

        rebuildTrafficBySourceTable();
        rebuildByIndexTable();
        rebuildFileTrafficBySourceTable();
        rebuildFileByIndexTable();
        updateTablePreferredHeight(trafficBySourceTable);
        updateTablePreferredHeight(byIndexTable);
        updateTablePreferredHeight(fileTrafficBySourceTable);
        updateTablePreferredHeight(fileByIndexTable);
        updateSectionVisibility();
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
        List<String> sortedKeys = new ArrayList<>(ExportStats.getIndexKeys());
        sortedKeys.sort(String::compareToIgnoreCase);
        for (String indexKey : sortedKeys) {
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

    private void rebuildFileTrafficBySourceTable() {
        fileTrafficBySourceModel.setRowCount(0);
        long sourceTotalSuccess = 0;
        long sourceTotalFailure = 0;
        for (String sourceKey : FileExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            long sourceSuccess = resolveFileSourceSuccess(sourceKey);
            long sourceFailure = resolveFileSourceFailure(sourceKey);
            sourceTotalSuccess += sourceSuccess;
            sourceTotalFailure += sourceFailure;
            fileTrafficBySourceModel.addRow(new Object[] {
                    formatKeyLabel(sourceKey),
                    sourceSuccess,
                    0,
                    0,
                    sourceFailure,
                    "-",
                    "-"
            });
        }
        fileTrafficBySourceModel.addRow(new Object[] { "Total", sourceTotalSuccess, 0, 0, sourceTotalFailure, "-", "-" });
    }

    private void rebuildFileByIndexTable() {
        fileByIndexModel.setRowCount(0);
        List<String> sortedKeys = new ArrayList<>(FileExportStats.getIndexKeys());
        sortedKeys.sort(String::compareToIgnoreCase);
        for (String indexKey : sortedKeys) {
            long success = FileExportStats.getSuccessCount(indexKey);
            long failure = FileExportStats.getFailureCount(indexKey);
            long lastWriteMs = FileExportStats.getLastWriteDurationMs(indexKey);
            String lastWriteStr = lastWriteMs >= 0 ? String.valueOf(lastWriteMs) : "-";
            String lastError = FileExportStats.getLastError(indexKey);
            String errStr = lastError != null ? truncateForColumn(lastError, ERROR_COL_MAX) : "-";
            fileByIndexModel.addRow(new Object[] {
                    formatKeyLabel(indexKey), success, 0, 0, failure, lastWriteStr, errStr
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
        if (table.getRowSorter() instanceof TableRowSorter<?> sorter) {
            for (int columnIndex = 1; columnIndex <= 5 && columnIndex < table.getColumnCount(); columnIndex++) {
                sorter.setComparator(columnIndex, StatsPanel::compareNumericCell);
            }
        }
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

    private static MetricCardState addGroupedMetricCard(JPanel parent, String title, List<MetricSection> sections) {
        JPanel card = new JPanel();
        card.setName("miscStatsCard");
        card.setLayout(new javax.swing.BoxLayout(card, javax.swing.BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createTitledBorder(title));
        card.setOpaque(false);
        int maxKeyWidth = 0;
        for (MetricSection section : sections) {
            for (String key : section.keys()) {
                JLabel probe = new JLabel(key);
                probe.setFont(CARD_KEY_FONT);
                maxKeyWidth = Math.max(maxKeyWidth, probe.getPreferredSize().width);
            }
        }
        Map<String, JLabel> values = new HashMap<>();
        Map<String, List<Component>> sectionComponents = new HashMap<>();
        int rowIndex = 0;
        for (MetricSection section : sections) {
            JLabel sectionLabel = new JLabel(section.title());
            sectionLabel.setName("miscStats.section." + section.title());
            sectionLabel.setForeground(TEXT_FG);
            sectionLabel.setFont(CARD_KEY_FONT.deriveFont(Font.BOLD));
            sectionLabel.setBorder(BorderFactory.createEmptyBorder(rowIndex == 0 ? 0 : 4, 6, 2, 6));
            sectionLabel.setAlignmentX(LEFT_ALIGNMENT);
            Dimension sectionPref = sectionLabel.getPreferredSize();
            sectionLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, sectionPref.height));
            card.add(sectionLabel);
            List<Component> components = new ArrayList<>();
            components.add(sectionLabel);
            sectionComponents.put(section.title(), components);
            for (int i = 0; i < section.keys().length; i++) {
                String key = section.keys()[i];
                JComponent row = new JPanel(new BorderLayout(10, 0));
                row.setName("miscStats.row." + section.title() + "." + i);
                row.setOpaque(true);
                row.setBackground(rowBackground(rowIndex));
                row.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
                row.setAlignmentX(LEFT_ALIGNMENT);

                JLabel keyLabel = new JLabel(key);
                keyLabel.setForeground(TEXT_FG);
                keyLabel.setFont(CARD_KEY_FONT);
                keyLabel.setPreferredSize(new Dimension(maxKeyWidth, keyLabel.getPreferredSize().height));

                JLabel valueLabel = new JLabel("-");
                valueLabel.setHorizontalAlignment(SwingConstants.LEFT);
                valueLabel.setForeground(TEXT_FG);
                valueLabel.setFont(CARD_VALUE_FONT);
                values.put(key, valueLabel);

                row.add(keyLabel, BorderLayout.WEST);
                row.add(valueLabel, BorderLayout.CENTER);
                Dimension rowPref = row.getPreferredSize();
                row.setMaximumSize(new Dimension(Integer.MAX_VALUE, rowPref.height));
                card.add(row);
                components.add(row);
                rowIndex++;
            }
        }
        card.add(javax.swing.Box.createVerticalGlue());
        Dimension preferred = card.getPreferredSize();
        card.setPreferredSize(new Dimension(Math.max(520, preferred.width), preferred.height));
        card.setMinimumSize(new Dimension(420, preferred.height));
        parent.add(card);
        return new MetricCardState(card, values, sectionComponents);
    }

    private static Color rowBackground(int rowIndex) {
        Color base = UIManager.getColor("Table.background");
        if (base == null) {
            base = UIManager.getColor("Panel.background");
        }
        if (base == null) {
            base = new Color(60, 60, 60);
        }
        Color alternate = UIManager.getColor("Table.alternateRowColor");
        if (alternate == null) {
            int delta = isDark(base) ? 8 : -8;
            alternate = adjust(base, delta);
        }
        return (rowIndex % 2 == 0) ? base : alternate;
    }

    private static boolean isDark(Color color) {
        return ((color.getRed() * 299) + (color.getGreen() * 587) + (color.getBlue() * 114)) / 1000 < 128;
    }

    private static Font uiFont(int style, float size) {
        Font base = UIManager.getFont("Label.font");
        if (base == null) {
            base = new JLabel().getFont();
        }
        if (base == null) {
            base = new Font("SansSerif", Font.PLAIN, Math.round(size));
        }
        return base.deriveFont(style, size);
    }

    private static Color uiColor(String key, Color fallback) {
        Color color = UIManager.getColor(key);
        return color != null ? color : fallback;
    }

    private static Color adjust(Color color, int delta) {
        return new Color(
                Math.clamp(color.getRed() + delta, 0, 255),
                Math.clamp(color.getGreen() + delta, 0, 255),
                Math.clamp(color.getBlue() + delta, 0, 255)
        );
    }

    private void updateDashboardSectionSizing() {
        int leftTableHeight = trafficBySourceTable.getPreferredSize().height
                + trafficBySourceTable.getTableHeader().getPreferredSize().height + 28;
        int rightTableHeight = byIndexTable.getPreferredSize().height
                + byIndexTable.getTableHeader().getPreferredSize().height + 28;
        int tablesHeight = Math.max(leftTableHeight, rightTableHeight);
        int fileLeftTableHeight = fileTrafficBySourceTable.getPreferredSize().height
                + fileTrafficBySourceTable.getTableHeader().getPreferredSize().height + 28;
        int fileRightTableHeight = fileByIndexTable.getPreferredSize().height
                + fileByIndexTable.getTableHeader().getPreferredSize().height + 28;
        int fileTablesHeight = Math.max(fileLeftTableHeight, fileRightTableHeight);
        tablesRow.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, tablesHeight));
        tablesRow.setMinimumSize(new Dimension(800, tablesHeight));
        fileTablesRow.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, fileTablesHeight));
        fileTablesRow.setMinimumSize(new Dimension(800, fileTablesHeight));

        int visibleChartCount = visibleChartPanelCount();
        int visibleLegendHeight = sharedLegendPanel.isVisible() ? sharedLegendPanel.getPreferredSize().height + 4 : 0;
        int chartsHeight = chartsPanel.isVisible()
                ? Math.max(0, visibleChartCount * (CHART_PANEL_HEIGHT / 2)) + visibleLegendHeight
                : 0;
        chartsPanel.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, chartsHeight));

        int cardsHeight = preferredHeightOf(cardsRow);
        cardsRow.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, cardsHeight));
        cardsRow.setMinimumSize(new Dimension(800, cardsHeight));
        cardsRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, cardsHeight));

        int lowerHeight = preferredHeightOf(lowerPanel);
        lowerPanel.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, lowerHeight));

        int requiredHeight = chartsHeight
                + lowerHeight
                + CONTENT_VERTICAL_PADDING;
        int dynamicPanelHeight = Math.max(PANEL_BASE_HEIGHT, requiredHeight);
        setPreferredSize(new Dimension(PANEL_BASE_WIDTH, dynamicPanelHeight));
    }

    private static int preferredHeightOf(JPanel panel) {
        return Math.max(0, panel.getLayout().preferredLayoutSize(panel).height);
    }

    /**
     * Shows only the sink-specific chart and table sections enabled by the current runtime config.
     *
     * <p>Files sections appear above OpenSearch sections. One sink is always expected to remain
     * enabled, so the shared legend stays visible whenever at least one chart section is shown.</p>
     */
    private void updateSectionVisibility() {
        boolean fileVisible = isFileSectionEnabled();
        boolean openSearchVisible = isOpenSearchSectionEnabled();
        moveLegendToFirstVisibleSection(fileVisible, openSearchVisible);

        fileChartsSectionPanel.setVisible(fileVisible);
        fileTablesRow.setVisible(fileVisible);

        openSearchChartsSectionPanel.setVisible(openSearchVisible);
        tablesRow.setVisible(openSearchVisible);
        updateMiscStatsSectionVisibility(fileVisible, openSearchVisible);

        updateChartDomainLabels(fileVisible, openSearchVisible);
        chartsPanel.setVisible(fileVisible || openSearchVisible);
        sharedLegendPanel.setVisible(fileVisible || openSearchVisible);
    }

    /**
     * Shows only the Misc Stats groups that apply to the active destinations.
     *
     * <p>Caller must invoke on the EDT because this method mutates Swing component visibility and
     * triggers layout/paint work on {@link #miscStatsCard}. The {@code Global} group always
     * remains visible, while {@code Files} and {@code OpenSearch} follow the currently visible
     * lower-panel sections.</p>
     *
     * @param fileVisible whether the Files metrics group should be visible
     * @param openSearchVisible whether the OpenSearch metrics group should be visible
     */
    private void updateMiscStatsSectionVisibility(boolean fileVisible, boolean openSearchVisible) {
        setMiscSectionVisible("Global", true);
        setMiscSectionVisible("OpenSearch", openSearchVisible);
        setMiscSectionVisible("Files", fileVisible);
        miscStatsCard.revalidate();
        miscStatsCard.repaint();
    }

    /**
     * Applies visibility to all components that belong to one Misc Stats group.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param title section title used as the lookup key in {@link #miscSectionComponents}
     * @param visible whether the section label and rows should be shown
     */
    private void setMiscSectionVisible(String title, boolean visible) {
        List<Component> components = miscSectionComponents.get(title);
        if (components == null) {
            return;
        }
        for (Component component : components) {
            component.setVisible(visible);
        }
    }

    private void moveLegendToFirstVisibleSection(boolean fileVisible, boolean openSearchVisible) {
        JPanel target = fileVisible ? fileChartsSectionPanel : (openSearchVisible ? openSearchChartsSectionPanel : null);
        if (target == null) {
            return;
        }
        if (sharedLegendPanel.getParent() == target) {
            return;
        }
        java.awt.Container parent = sharedLegendPanel.getParent();
        if (parent != null) {
            parent.remove(sharedLegendPanel);
        }
        target.add(sharedLegendPanel, 0);
        target.revalidate();
        target.repaint();
    }

    private void updateChartDomainLabels(boolean fileVisible, boolean openSearchVisible) {
        setChartDomainLabel(fileDocsChart, null);
        setChartDomainLabel(docsChart, null);
        setChartDomainLabel(fileKibChart, fileVisible && !openSearchVisible ? "Time" : null);
        setChartDomainLabel(kibChart, openSearchVisible ? "Time" : null);
    }

    /** Returns whether the current runtime config has file export selected. */
    private static boolean isFileSectionEnabled() {
        return RuntimeConfig.isAnyFileExportEnabled();
    }

    /** Returns whether the current runtime config has OpenSearch export selected. */
    private static boolean isOpenSearchSectionEnabled() {
        var current = RuntimeConfig.getState();
        return current != null
                && current.sinks() != null
                && current.sinks().osEnabled();
    }

    private int visibleChartPanelCount() {
        int count = 0;
        if (fileChartsSectionPanel.isVisible()) {
            count++;
            count++;
        }
        if (openSearchChartsSectionPanel.isVisible()) {
            count++;
            count++;
        }
        return count;
    }

    private static JPanel buildChartSection(JPanel topChartPanel, JPanel bottomChartPanel, int bottomGap) {
        JPanel section = new JPanel();
        section.setLayout(new javax.swing.BoxLayout(section, javax.swing.BoxLayout.Y_AXIS));
        section.setOpaque(false);
        section.setBorder(BorderFactory.createEmptyBorder(0, 0, bottomGap, 0));
        section.add(topChartPanel);
        section.add(javax.swing.Box.createVerticalStrut(12));
        section.add(bottomChartPanel);
        return section;
    }

    private static String formatWhole(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    /**
     * Formats exported-byte totals with a human-readable unit.
     *
     * <p>Uses binary thresholds for readability while keeping familiar unit labels in the UI.
     * Values below 1 KB remain in bytes; larger values are shown in KB, MB, or GB.</p>
     */
    private static String formatHumanReadableBytes(long bytes) {
        long safeBytes = Math.max(0L, bytes);
        double value = safeBytes;
        String unit = "B";
        if (safeBytes >= 1024L * 1024L * 1024L) {
            value = safeBytes / (1024.0 * 1024.0 * 1024.0);
            unit = "GB";
        } else if (safeBytes >= 1024L * 1024L) {
            value = safeBytes / (1024.0 * 1024.0);
            unit = "MB";
        } else if (safeBytes >= 1024L) {
            value = safeBytes / 1024.0;
            unit = "KB";
        }
        if ("B".equals(unit)) {
            return formatWhole(safeBytes) + " " + unit;
        }
        return DECIMAL_ONE.format(value) + " " + unit;
    }

    private static void updateTablePreferredHeight(JTable table) {
        updatePrimaryLabelColumnWidth(table);
        int rows = Math.max(1, table.getRowCount());
        int headerHeight = table.getTableHeader() != null ? table.getTableHeader().getPreferredSize().height : 24;
        int totalHeight = headerHeight + (rows * table.getRowHeight()) + 6;
        int preferredWidth = Math.max(700, table.getPreferredSize().width);
        table.setPreferredScrollableViewportSize(new Dimension(preferredWidth, totalHeight));
        table.setPreferredSize(new Dimension(preferredWidth, Math.max(1, totalHeight - headerHeight)));
    }

    /**
     * Packs the first label column to the widest visible label so entries such as
     * {@code Repeater History} are not clipped in fixed-width tables.
     */
    private static void updatePrimaryLabelColumnWidth(JTable table) {
        if (table == null || table.getColumnCount() == 0) {
            return;
        }
        javax.swing.table.TableColumn column = table.getColumnModel().getColumn(0);
        int preferredWidth = preferredColumnWidth(table, 0);
        column.setPreferredWidth(preferredWidth);
        column.setWidth(preferredWidth);
    }

    /**
     * Measures the larger of the header text or any visible cell in the column, then adds a small
     * padding buffer so packed labels do not render flush against the divider.
     */
    private static int preferredColumnWidth(JTable table, int columnIndex) {
        int widest = 0;
        javax.swing.table.TableColumn column = table.getColumnModel().getColumn(columnIndex);
        javax.swing.table.TableCellRenderer headerRenderer = column.getHeaderRenderer();
        if (headerRenderer == null && table.getTableHeader() != null) {
            headerRenderer = table.getTableHeader().getDefaultRenderer();
        }
        if (headerRenderer != null) {
            Component headerComponent = headerRenderer.getTableCellRendererComponent(
                    table,
                    column.getHeaderValue(),
                    false,
                    false,
                    -1,
                    columnIndex);
            widest = Math.max(widest, headerComponent.getPreferredSize().width);
        }
        for (int rowIndex = 0; rowIndex < table.getRowCount(); rowIndex++) {
            javax.swing.table.TableCellRenderer renderer = table.getCellRenderer(rowIndex, columnIndex);
            Component cellComponent = table.prepareRenderer(renderer, rowIndex, columnIndex);
            widest = Math.max(widest, cellComponent.getPreferredSize().width);
        }
        return Math.max(120, widest + 18);
    }

    private static int compareNumericCell(Object left, Object right) {
        Long leftValue = toSortableLong(left);
        Long rightValue = toSortableLong(right);
        if (leftValue == null && rightValue == null) {
            return 0;
        }
        if (leftValue == null) {
            return -1;
        }
        if (rightValue == null) {
            return 1;
        }
        return Long.compare(leftValue, rightValue);
    }

    private static Long toSortableLong(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        String text = value instanceof String stringValue
                ? stringValue.trim()
                : value.toString().trim();
        if (text.isEmpty() || "-".equals(text)) {
            return null;
        }
        try {
            return Long.valueOf(text.indexOf(',') >= 0 ? text.replace(",", "") : text);
        } catch (NumberFormatException ignored) {
            return null;
        }
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
                previousFileSuccessByIndex.put(indexKey, FileExportStats.getSuccessCount(indexKey));
                previousFileBytesByIndex.put(indexKey, FileExportStats.getExportedBytes(indexKey));
                ensureFileSeries(indexKey);
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

            ensureFileSeries(indexKey);
            long currentFileSuccess = FileExportStats.getSuccessCount(indexKey);
            long currentFileBytes = FileExportStats.getExportedBytes(indexKey);
            long previousFileSuccess = previousFileSuccessByIndex.getOrDefault(indexKey, currentFileSuccess);
            long previousFileBytes = previousFileBytesByIndex.getOrDefault(indexKey, currentFileBytes);

            double fileDocsPerSec = Math.max(0.0, (currentFileSuccess - previousFileSuccess) / elapsedSec);
            double fileKibPerSec = Math.max(0.0, (currentFileBytes - previousFileBytes) / 1024.0 / elapsedSec);
            fileDocsSeriesByIndex.get(indexKey).addOrUpdate(tick, fileDocsPerSec);
            fileKibSeriesByIndex.get(indexKey).addOrUpdate(tick, fileKibPerSec);

            previousFileSuccessByIndex.put(indexKey, currentFileSuccess);
            previousFileBytesByIndex.put(indexKey, currentFileBytes);
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

    private void ensureFileSeries(String indexKey) {
        fileDocsSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            fileDocsPerSecondDataset.addSeries(s);
            return s;
        });
        fileKibSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            fileKibPerSecondDataset.addSeries(s);
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
        Color chartBackground = chartBackgroundPaint();
        Color plotBackground = plotBackgroundPaint();
        Color gridForeground = gridPaint();
        JFreeChart chart = ChartFactory.createTimeSeriesChart(title, "Time", yLabel, dataset, showLegend, false, false);
        chart.setBackgroundPaint(chartBackground);
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
        plot.setBackgroundPaint(plotBackground);
        plot.setDomainGridlinePaint(gridForeground);
        plot.setRangeGridlinePaint(gridForeground);
        plot.setDomainGridlinesVisible(true);
        plot.setRangeGridlinesVisible(true);
        ValueAxis domain = plot.getDomainAxis();
        ValueAxis range = plot.getRangeAxis();
        if (range instanceof NumberAxis numberAxis) {
            // Throughput charts are non-negative metrics; keep zero anchored at the bottom.
            numberAxis.setRangeType(RangeType.POSITIVE);
            numberAxis.setAutoRangeIncludesZero(true);
            numberAxis.setAutoRangeStickyZero(true);
            numberAxis.setLowerMargin(0.0);
            // Smoothed spline peaks can rise slightly above raw samples; keep some headroom.
            numberAxis.setUpperMargin(0.12);
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
        renderer.setDefaultStroke(new BasicStroke(CHART_LINE_STROKE_WIDTH, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(chartBackground);
            chart.getLegend().setItemPaint(TEXT_FG);
            chart.getLegend().setItemFont(CHART_LEGEND_FONT);
        }
        return chart;
    }

    private void applyChartStyles() {
        applyChartStyle(docsChart);
        applyChartStyle(kibChart);
        applyChartStyle(fileDocsChart);
        applyChartStyle(fileKibChart);
    }

    private void applyChartStyle(JFreeChart chart) {
        XYPlot plot = chart.getXYPlot();
        XYLineAndShapeRenderer renderer = rendererForStyle(chart);
        renderer.setDefaultStroke(new BasicStroke(CHART_LINE_STROKE_WIDTH, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        for (int i = 0; i < SERIES_STYLES.length; i++) {
            renderer.setSeriesPaint(i, seriesLinePaint(i));
            renderer.setSeriesStroke(i, seriesStroke(i));
            renderer.setSeriesShape(i, seriesMarkerShape(i));
            renderer.setSeriesShapesVisible(i, seriesShapesVisible(i));
            renderer.setSeriesShapesFilled(i, seriesShapesFilled(i));
        }
        if (chartStyleIndex == 1) {
            XYSplineRenderer slickRenderer = (XYSplineRenderer) renderer;
            slickRenderer.setFillType(XYSplineRenderer.FillType.TO_LOWER_BOUND);
            for (int i = 0; i < SERIES_STYLES.length; i++) {
                slickRenderer.setSeriesFillPaint(i, seriesAreaPaint(i));
            }
        }
        plot.setDataset(1, null);
        plot.setRenderer(1, null);
    }

    private XYLineAndShapeRenderer rendererForStyle(JFreeChart chart) {
        XYPlot plot = chart.getXYPlot();
        if (chartStyleIndex == 1) {
            if (plot.getRenderer() instanceof XYSplineRenderer splineRenderer) {
                splineRenderer.setPrecision(12);
                return splineRenderer;
            }
            XYSplineRenderer splineRenderer = new XYSplineRenderer(12);
            plot.setRenderer(splineRenderer);
            return splineRenderer;
        }
        if (plot.getRenderer() instanceof XYLineAndShapeRenderer lineRenderer
                && !(lineRenderer instanceof XYSplineRenderer)) {
            return lineRenderer;
        }
        XYLineAndShapeRenderer lineRenderer = new XYLineAndShapeRenderer();
        plot.setRenderer(lineRenderer);
        return lineRenderer;
    }

    private static void setChartDomainLabel(JFreeChart chart, String label) {
        ValueAxis domain = chart.getXYPlot().getDomainAxis();
        if (domain != null) {
            domain.setLabel(label);
        }
    }

    private static ChartPanel createRateChartPanel(JFreeChart chart) {
        ChartPanel panel = new ChartPanel(chart);
        panel.setMouseWheelEnabled(false);
        panel.setPopupMenu(null);
        return panel;
    }

    private JPanel createSharedLegendPanel() {
        JPanel legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        legendPanel.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 0));
        legendPanel.setOpaque(false);
        return legendPanel;
    }

    private JButton createChartStyleButton() {
        JButton button = new Tooltips.HtmlButton(chartStyleButtonLabel());
        button.setFocusable(false);
        Font buttonFont = UIManager.getFont("Button.font");
        button.setFont(uiFont(Font.PLAIN, buttonFont == null ? 12f : buttonFont.getSize2D()));
        Tooltips.apply(button, Tooltips.htmlRaw("Cycle chart styles: <b>Simple</b>, <b>Smooth</b>, and <b>Accessible</b>."));
        button.addActionListener(event -> cycleChartStyle());
        return button;
    }

    private void refreshSharedLegendPanel() {
        sharedLegendPanel.removeAll();
        sharedLegendPanel.add(chartStyleButton);
        for (int i = 0; i < SERIES_STYLES.length; i++) {
            JLabel legendItem = new JLabel(SERIES_STYLES[i].label(), new LegendSampleIcon(i), SwingConstants.LEFT);
            legendItem.setForeground(TEXT_FG);
            legendItem.setFont(CHART_LEGEND_FONT);
            legendItem.setIconTextGap(6);
            sharedLegendPanel.add(legendItem);
        }
        chartStyleButton.setText(chartStyleButtonLabel());
        sharedLegendPanel.revalidate();
        sharedLegendPanel.repaint();
    }

    private void cycleChartStyle() {
        chartStyleIndex = (chartStyleIndex + 1) % CHART_STYLE_NAMES.length;
        RuntimeConfig.updateStatsChartStyle(chartStyleIndex + 1);
        applyChartStyles();
        refreshSharedLegendPanel();
        refreshDashboard();
    }

    private String chartStyleButtonLabel() {
        return CHART_STYLE_NAMES[chartStyleIndex];
    }

    private static boolean isDarkTheme() {
        return isDark(uiColor("Panel.background", new Color(38, 38, 38)));
    }

    private static Color chartBackgroundPaint() {
        return uiColor("Panel.background", new Color(38, 38, 38));
    }

    private static Color plotBackgroundPaint() {
        Color plotBackground = uiColor("Table.background", chartBackgroundPaint());
        if (plotBackground.equals(chartBackgroundPaint())) {
            return adjust(plotBackground, isDark(plotBackground) ? 6 : -6);
        }
        return plotBackground;
    }

    private static Color gridPaint() {
        Color separator = uiColor("Separator.foreground", adjust(plotBackgroundPaint(), isDarkTheme() ? 28 : -28));
        if (separator.equals(chartBackgroundPaint())) {
            return adjust(separator, isDarkTheme() ? 32 : -32);
        }
        return separator;
    }

    private Color seriesSolidColor(int index) {
        return SERIES_STYLES[index].paint();
    }

    private Paint seriesPaint(int index) {
        SeriesStyle base = SERIES_STYLES[index];
        return switch (chartStyleIndex) {
            case 0 -> withAlpha(base.paint(), isDarkTheme() ? 235 : 210);
            case 1 -> slickGradientAreaPaint(base);
            case 2 -> base.paint();
            default -> base.paint();
        };
    }

    private Paint seriesLinePaint(int index) {
        return chartStyleIndex == 1
                ? withAlpha(seriesSolidColor(index), isDarkTheme() ? 245 : 225)
                : seriesPaint(index);
    }

    private Paint seriesAreaPaint(int index) {
        return chartStyleIndex == 1 ? seriesPaint(index) : seriesLinePaint(index);
    }

    private Paint legendPaint(int index, int topY, int bottomY) {
        if (chartStyleIndex == 1) {
            Color top = withAlpha(seriesSolidColor(index), isDarkTheme() ? 235 : 210);
            Color bottom = withAlpha(adjust(seriesSolidColor(index), isDarkTheme() ? -34 : -26), isDarkTheme() ? 130 : 150);
            return new GradientPaint(0f, topY, top, 0f, bottomY, bottom);
        }
        return seriesPaint(index);
    }

    private BasicStroke seriesStroke(int index) {
        return switch (chartStyleIndex) {
            case 0 -> new BasicStroke(2.1f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
            case 1 -> new BasicStroke(2.25f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
            case 2 -> SERIES_STYLES[index].stroke(CHART_LINE_STROKE_WIDTH);
            default -> SERIES_STYLES[index].stroke(CHART_LINE_STROKE_WIDTH);
        };
    }

    private Shape seriesMarkerShape(int index) {
        return switch (chartStyleIndex) {
            case 0 -> SERIES_STYLES[index].markerShape();
            case 1 -> SERIES_STYLES[index].markerShape();
            case 2 -> SERIES_STYLES[index].markerShape();
            case 3 -> SERIES_STYLES[index].markerShape();
            default -> SERIES_STYLES[index].markerShape();
        };
    }

    private boolean seriesShapesVisible(int index) {
        return index >= 0 && switch (chartStyleIndex) {
            case 0 -> false;
            case 1 -> false;
            case 2 -> true;
            default -> true;
        };
    }

    private boolean seriesShapesFilled(int index) {
        return switch (chartStyleIndex) {
            case 0 -> false;
            case 1 -> false;
            case 2 -> SERIES_STYLES[index].markerFilled();
            default -> SERIES_STYLES[index].markerFilled();
        };
    }

    private Paint slickGradientAreaPaint(SeriesStyle base) {
        Color top = withAlpha(base.paint(), isDarkTheme() ? 235 : 215);
        Color bottom = withAlpha(adjust(base.paint(), isDarkTheme() ? -44 : -34), isDarkTheme() ? 80 : 105);
        return new GradientPaint(0f, 0f, top, 0f, CHART_PANEL_HEIGHT / 2f, bottom, true);
    }

    private static Color withAlpha(Color color, int alpha) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue(), Math.clamp(alpha, 0, 255));
    }

    private static Shape circleMarker(float size) {
        float half = size / 2f;
        return new Ellipse2D.Float(-half, -half, size, size);
    }

    private static Shape squareMarker(float size) {
        float half = size / 2f;
        return new Rectangle2D.Float(-half, -half, size, size);
    }

    private static Shape diamondMarker(float size) {
        float half = size / 2f;
        Path2D.Float path = new Path2D.Float();
        path.moveTo(0, -half);
        path.lineTo(half, 0);
        path.lineTo(0, half);
        path.lineTo(-half, 0);
        path.closePath();
        return path;
    }

    private static Shape triangleMarker(float size) {
        float half = size / 2f;
        Path2D.Float path = new Path2D.Float();
        path.moveTo(0, -half);
        path.lineTo(half, half);
        path.lineTo(-half, half);
        path.closePath();
        return path;
    }

    private static Shape crossMarker(float size) {
        float half = size / 2f;
        Path2D.Float path = new Path2D.Float();
        path.moveTo(-half, -half);
        path.lineTo(half, half);
        path.moveTo(-half, half);
        path.lineTo(half, -half);
        return path;
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
        updateDomainRange(fileDocsChart, minMs, nowMs);
        updateDomainRange(fileKibChart, minMs, nowMs);
        applyReasonableDefaultRange(docsChart, docsPerSecondDataset, DEFAULT_RATE_RANGE_MAX);
        applyReasonableDefaultRange(kibChart, kibPerSecondDataset, DEFAULT_RATE_RANGE_MAX);
        applyReasonableDefaultRange(fileDocsChart, fileDocsPerSecondDataset, DEFAULT_RATE_RANGE_MAX);
        applyReasonableDefaultRange(fileKibChart, fileKibPerSecondDataset, DEFAULT_RATE_RANGE_MAX);
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

    private record MetricSection(String title, String[] keys) { }

    private record MetricCardState(
            JPanel card,
            Map<String, JLabel> values,
            Map<String, List<Component>> sections) { }

    /**
     * Starts periodic refresh while this panel is in the display hierarchy.
     *
     * <p>Burp may remove/add tab content on tab switches. Keeping timer lifecycle tied to
     * add/remove prevents unnecessary refresh work while the panel is not visible.</p>
     */
    @Override
    public void addNotify() {
        super.addNotify();
        RuntimeConfig.registerStateListener(runtimeStateListener);
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
        RuntimeConfig.unregisterStateListener(runtimeStateListener);
        super.removeNotify();
    }

    private void onRuntimeStateChanged(ConfigState.State state) {
        int runtimeStyle = state == null || state.uiPreferences() == null
                ? ConfigState.DEFAULT_STATS_CHART_STYLE
                : state.uiPreferences().statsChartStyle();
        int normalizedStyle = Math.clamp(runtimeStyle, 1, CHART_STYLE_NAMES.length) - 1;
        Runnable apply = () -> {
            if (chartStyleIndex == normalizedStyle) {
                return;
            }
            chartStyleIndex = normalizedStyle;
            applyChartStyles();
            refreshSharedLegendPanel();
            repaint();
        };
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            javax.swing.SwingUtilities.invokeLater(apply);
        }
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
        sb.append("  spill queue: docs=")
                .append(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSpillSize())
                .append(" bytes=")
                .append(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSpillBytes())
                .append(" oldestAgeMs=")
                .append(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getCurrentSpillOldestAgeMs())
                .append(" enq/deq/drops=")
                .append(ExportStats.getTrafficSpillEnqueued()).append("/")
                .append(ExportStats.getTrafficSpillDequeued()).append("/")
                .append(ExportStats.getTrafficSpillDrops()).append("\n");
        sb.append("  traffic drop reasons: spill_rejected_drop_oldest=")
                .append(ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest"))
                .append(" queue_contention_drop=")
                .append(ExportStats.getTrafficDropReasonCount("queue_contention_drop"))
                .append(" spill_requeue_failed_drop=")
                .append(ExportStats.getTrafficDropReasonCount("spill_requeue_failed_drop"))
                .append(" spill_retention_prune=")
                .append(ExportStats.getTrafficSpillExpiredPruned())
                .append("\n");
        sb.append("  spill recovered (startup): ").append(ExportStats.getTrafficSpillRecovered()).append("\n");
        sb.append("  spill directory: ").append(ai.attackframework.tools.burp.sinks.TrafficExportQueue.getSpillDirectoryPath()).append("\n");
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
        sb.append("  total docs exported: ").append(totalSuccess).append("\n");
        sb.append("  total failures: ").append(totalFailure).append("\n\n");

        // Traffic by source
        sb.append("Traffic by source\n");
        sb.append(String.format("  %-22s %-12s %-10s%n", "Source", "Docs exported", "Failures"));
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
                "Index", "Docs exported", "Queued", "Rty drop", "Failures", "Last push (ms)", "Last error"));
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

        long totalFileSuccess = FileExportStats.getTotalSuccessCount();
        long totalFileFailure = FileExportStats.getTotalFailureCount();
        sb.append("File totals (this session)\n");
        sb.append("  total docs exported: ").append(totalFileSuccess).append("\n");
        sb.append("  total failures: ").append(totalFileFailure).append("\n\n");

        sb.append("File traffic by source\n");
        sb.append(String.format("  %-22s %-12s %-10s%n", "Source", "Docs exported", "Failures"));
        sb.append("  ").append("-".repeat(22)).append(" ").append("-".repeat(12)).append(" ").append("-".repeat(10)).append("\n");
        long fileSourceTotalSuccess = 0;
        long fileSourceTotalFailure = 0;
        for (String sourceKey : FileExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            long sourceSuccess = resolveFileSourceSuccess(sourceKey);
            long sourceFailure = resolveFileSourceFailure(sourceKey);
            fileSourceTotalSuccess += sourceSuccess;
            fileSourceTotalFailure += sourceFailure;
            sb.append(String.format("  %-22s %-12d %-10d%n", sourceKey.toLowerCase(Locale.ROOT), sourceSuccess, sourceFailure));
        }
        sb.append(String.format("  %-22s %-12d %-10d%n%n", "total", fileSourceTotalSuccess, fileSourceTotalFailure));

        sb.append("File by index\n");
        sb.append(String.format("  %-10s %-12s %-8s %-8s %-10s %-14s  %s%n",
                "Index", "Docs exported", "Queued", "Rty drop", "Failures", "Last push (ms)", "Last error"));
        sb.append("  ").append("-".repeat(10)).append(" ").append("-".repeat(12)).append(" ").append("-".repeat(8)).append(" ").append("-".repeat(8)).append(" ").append("-".repeat(10)).append(" ").append("-".repeat(14)).append("  ").append("-".repeat(ERROR_COL_MAX)).append("\n");
        for (String indexKey : FileExportStats.getIndexKeys()) {
            long success = FileExportStats.getSuccessCount(indexKey);
            long failure = FileExportStats.getFailureCount(indexKey);
            long lastPushMs = FileExportStats.getLastWriteDurationMs(indexKey);
            String lastPushStr = lastPushMs >= 0 ? String.valueOf(lastPushMs) : "-";
            String lastError = FileExportStats.getLastError(indexKey);
            String errStr = lastError != null ? truncateForColumn(lastError, ERROR_COL_MAX) : "-";
            sb.append(String.format("  %-10s %-12d %-8d %-8d %-10d %-14s  %s%n",
                    indexKey, success, 0, 0, failure, lastPushStr, errStr));
        }
        sb.append("\n");

        return sb.toString();
    }

    /**
     * Resolves "Traffic by source" docs exported count for a source key.
     *
     * <p>Most rows come from live captured tool-type counts. Proxy-history snapshot pushes and
     * proxy WebSocket exports are recorded separately, so include those under the
     * proxy_history row. Delegates to {@link TrafficRouteBucket} so the mapping stays consistent
     * across sinks and stats displays.</p>
     */
    private static long resolveSourceSuccess(String sourceKey) {
        return TrafficRouteBucket.resolveOpenSearchSourceSuccess(sourceKey);
    }

    /** Resolves "Traffic by source" failure count for a source key. */
    private static long resolveSourceFailure(String sourceKey) {
        return TrafficRouteBucket.resolveOpenSearchSourceFailure(sourceKey);
    }

    private static long resolveFileSourceSuccess(String sourceKey) {
        return TrafficRouteBucket.resolveFileSourceSuccess(sourceKey);
    }

    private static long resolveFileSourceFailure(String sourceKey) {
        return TrafficRouteBucket.resolveFileSourceFailure(sourceKey);
    }

    private static String truncateForColumn(String s, int maxLen) {
        if (s == null) return "-";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}
