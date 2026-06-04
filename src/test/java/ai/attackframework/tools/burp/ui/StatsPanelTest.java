package ai.attackframework.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.GradientPaint;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Shape;
import java.awt.image.BufferedImage;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JButton;
import javax.swing.JToolTip;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import static org.assertj.core.api.Assertions.assertThat;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.renderer.xy.XYSplineRenderer;
import org.jfree.data.RangeType;
import org.jfree.data.time.TimeSeries;
import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;

import ai.attackframework.tools.burp.testutils.Reflect;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

class StatsPanelTest {

    @Test
    void buildStatsText_containsExportStateAndSessionTotalsAndByIndex() {
        String text = StatsPanel.buildStatsText();

        assertThat(text).contains("Export state");
        assertThat(text).contains("export running:");
        assertThat(text).contains("traffic queue:");
        assertThat(text).contains("drops=");
        assertThat(text).contains("null tool/source hits:");
        assertThat(text).contains("throughput (last 10s):");
        assertThat(text).contains("docs/s");
        assertThat(text).contains("Efficiency");
        assertThat(text).contains("start click -> first successful traffic doc acknowledged (ms):");
        assertThat(text).contains("proxy-history last snapshot:");
        assertThat(text).doesNotContain("proxy-history recorded at:");

        assertThat(text).contains("Session totals (this session)");
        assertThat(text).contains("total docs exported:");
        assertThat(text).contains("total failures:");

        assertThat(text).contains("Traffic by source");
        assertThat(text).contains("Source");
        assertThat(text).contains("burp_ai");
        assertThat(text).contains("extensions");
        assertThat(text).contains("intruder");
        assertThat(text).contains("proxy");
        assertThat(text).contains("proxy_history");
        assertThat(text).contains("repeater");
        assertThat(text).contains("scanner");
        assertThat(text).contains("sequencer");
        assertThat(text).contains("total");

        assertThat(text).contains("By index");
        assertThat(text).contains("Index");
        assertThat(text).contains("Docs exported");
        assertThat(text).contains("Queued");
        assertThat(text).contains("Rty drop");
        assertThat(text).contains("Failures");
        assertThat(text).contains("Last push (ms)");
        assertThat(text).contains("Last error");

        assertThat(text).contains("traffic");
        assertThat(text).contains("exporter");
        assertThat(text).contains("settings");
        assertThat(text).contains("sitemap");
        assertThat(text).contains("findings");

        assertThat(text).doesNotContain("Process total (Burp + all extensions)");
        assertThat(text).doesNotContain("Our extension (attackframework-burp-exporter)");
        assertThat(text).doesNotContain("Burp + other extensions");
        assertThat(text).doesNotContain("heap (MB)");
        assertThat(text).doesNotContain("thread count:");

        assertThat(text).contains("heap used / max bytes:");
        assertThat(text).contains("heap committed bytes:");
        assertThat(text).contains("direct buffer used bytes:");
        assertThat(text).contains("mapped buffer used bytes:");
    }

    @Test
    void docsChart_usesReadableTimeAxis_andPositiveWholeNumberDefaults() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart docsChart = JFreeChart.class.cast(get(panel, "docsChart"));
        XYPlot plot = docsChart.getXYPlot();

        NumberAxis range = (NumberAxis) plot.getRangeAxis();
        assertThat(range.getRangeType()).isEqualTo(RangeType.POSITIVE);
        assertThat(range.getUpperMargin()).isEqualTo(0.20);
        assertThat(range.getLowerBound()).isEqualTo(0.0);
        assertThat(range.getUpperBound()).isEqualTo(10.0);

        DateAxis domain = (DateAxis) plot.getDomainAxis();
        assertThat(domain.isTickLabelsVisible()).isTrue();
        assertThat(domain.getDateFormatOverride()).isInstanceOf(SimpleDateFormat.class);
        assertThat(((SimpleDateFormat) domain.getDateFormatOverride()).toPattern()).isEqualTo("HH:mm:ss");
        assertThat(domain.getTickUnit().getUnitType()).isEqualTo(DateTickUnitType.SECOND);

        JFreeChart kibChart = JFreeChart.class.cast(get(panel, "kibChart"));
        NumberAxis kibRange = (NumberAxis) kibChart.getXYPlot().getRangeAxis();
        assertThat(kibRange.getRangeType()).isEqualTo(RangeType.POSITIVE);
        assertThat(kibRange.getLowerBound()).isEqualTo(0.0);
        assertThat(kibRange.getUpperBound()).isEqualTo(10.0);
    }

    @Test
    void refreshVisibleStats_addsSamplesEvenWhenPanelIsNotShowing() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        assertThat(onEdt(panel::isShowing)).isFalse();

        Map<String, TimeSeries> seriesByIndex = Map.class.cast(get(panel, "docsSeriesByIndex"));
        int before = onEdt(() -> {
            TimeSeries traffic = seriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        });

        ExportStats.recordSuccess("traffic", 3);
        Thread.sleep(20L);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        int after = onEdt(() -> {
            TimeSeries traffic = seriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        });
        assertThat(after).isGreaterThan(before);
    }

    @Test
    void mergedSinkTables_haveExpectedColumnSchema_andMiscStatsCardSpansFullWidth() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));

        // OpenSearch carries 8 columns including "Permanent Drops". File carries 5 columns
        // total: Index, Docs Exported, Failures, Last Push (ms), Last Error. The file sink
        // is synchronous to disk with no queue, no retry path, and no permanent-drop
        // concept, so those three columns are deliberately omitted from the file schema.
        // Both tables nest source rows under the Traffic index row.
        assertThat(indexModel.getColumnCount()).isEqualTo(8);
        assertThat(indexModel.getColumnName(0)).isEqualTo("Index");
        assertThat(indexModel.getColumnName(4)).isEqualTo("Permanent Drops");
        assertThat(fileIndexModel.getColumnCount()).isEqualTo(5);
        assertThat(fileIndexModel.getColumnName(0)).isEqualTo("Index");
        assertThat(fileIndexModel.getColumnName(1)).isEqualTo("Docs Exported");
        assertThat(fileIndexModel.getColumnName(2)).isEqualTo("Failures");
        assertThat(fileIndexModel.getColumnName(3)).isEqualTo("Last Push (ms)");
        assertThat(fileIndexModel.getColumnName(4)).isEqualTo("Last Error");
        assertThat(cardsRow.getComponentCount()).isEqualTo(1);
    }

    @Test
    void mergedSinkTables_packFirstColumnToFitIndentedRepeaterTabsSubRowLabel() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable openSearchTable = JTable.class.cast(get(panel, "byIndexTable"));
        JTable fileTable = JTable.class.cast(get(panel, "fileByIndexTable"));
        String subRowLabel = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT")) + "Repeater Tabs";

        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(firstColumnPreferredWidth(openSearchTable))
                .isGreaterThanOrEqualTo(requiredLabelColumnWidth(openSearchTable, subRowLabel));
        assertThat(firstColumnPreferredWidth(fileTable))
                .isGreaterThanOrEqualTo(requiredLabelColumnWidth(fileTable, subRowLabel));
    }

    @Test
    void byIndexTable_hasNoDefaultActiveSortKey() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = JTable.class.cast(get(panel, "byIndexTable"));
        RowSorter<? extends javax.swing.table.TableModel> sorter = byIndexTable.getRowSorter();
        assertThat(sorter).isNotNull();
        assertThat(sorter.getSortKeys()).isEmpty();
    }

    @Test
    void byIndexTable_remainsAlphabeticallySortedAfterRefresh() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = JTable.class.cast(get(panel, "byIndexTable"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordSuccess("traffic", 11);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        List<String> allRows = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int row = 0; row < byIndexTable.getRowCount(); row++) {
                rows.add(String.valueOf(byIndexTable.getValueAt(row, 0)));
            }
            return rows;
        });
        // The trailing "Total" summary row is appended unconditionally; before it sits a block
        // of indented traffic-source sub-rows that are nested under the Traffic index row but
        // not part of the alphabetical group. Strip the indented block and the Total row, then
        // verify the remaining index rows stay alphabetically sorted across rebuilds.
        assertThat(allRows).isNotEmpty();
        assertThat(allRows.get(allRows.size() - 1)).isEqualTo("Total");
        List<String> indexRows = new ArrayList<>();
        for (String row : allRows.subList(0, allRows.size() - 1)) {
            if (!row.startsWith(indent)) {
                indexRows.add(row);
            }
        }
        List<String> sorted = new ArrayList<>(indexRows);
        Collections.sort(sorted);
        assertThat(indexRows).isEqualTo(sorted);
    }

    @Test
    void refreshVisibleStats_logsFallbackHitsOnlyWhenValueIncreases() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        List<String> seenFallbackErrors = new ArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("ERROR".equals(level) && message.contains("Traffic tool/source fallback hits observed:")) {
                seenFallbackErrors.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            onEdt(() -> call(panel, "refreshVisibleStats"));
            seenFallbackErrors.clear();

            ExportStats.recordTrafficToolSourceFallback();
            onEdt(() -> call(panel, "refreshVisibleStats"));
            int afterIncrease = seenFallbackErrors.size();
            assertThat(afterIncrease).isEqualTo(1);

            onEdt(() -> call(panel, "refreshVisibleStats"));
            assertThat(seenFallbackErrors).hasSize(afterIncrease);

            ExportStats.recordTrafficToolSourceFallback();
            onEdt(() -> call(panel, "refreshVisibleStats"));
            assertThat(seenFallbackErrors).hasSize(afterIncrease + 1);
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void sharedLegendPanel_isLeftAlignedWithExpectedSeriesLabels() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(1, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel legendPanel = JPanel.class.cast(get(panel, "sharedLegendPanel"));
            assertThat(legendPanel.getLayout()).isInstanceOf(FlowLayout.class);
            FlowLayout layout = (FlowLayout) legendPanel.getLayout();
            assertThat(layout.getAlignment()).isEqualTo(FlowLayout.LEFT);
            Font expectedLegendFont = StatsPanel.chartLegendFont();
            Color expectedTextColor = Color.class.cast(getStatic(StatsPanel.class, "TEXT_FG"));
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));

            List<String> labels = new ArrayList<>();
            for (Component component : legendPanel.getComponents()) {
                if (component instanceof JLabel label) {
                    labels.add(label.getText());
                    assertThat(label.getHorizontalAlignment()).isEqualTo(SwingConstants.LEFT);
                    assertThat(label.getFont()).isEqualTo(expectedLegendFont);
                    assertThat(label.getForeground()).isEqualTo(expectedTextColor);
                    assertThat(label.getIcon()).isNotNull();
                }
            }
            assertThat(legendPanel.getComponent(0)).isSameAs(styleButton);
            assertThat(styleButton.getText()).isEqualTo("Simple");
            assertThat(styleButton.getFont().isBold()).isFalse();
            JToolTip styleToolTip = onEdt(styleButton::createToolTip);
            assertThat(styleToolTip.getComponent()).isSameAs(styleButton);
            assertThat(styleToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            assertThat(styleButton.getToolTipText())
                    .isEqualTo("<html>Cycle chart styles: <b>Simple</b>, <b>Smooth</b>, and <b>Accessible</b>.</html>");
            assertThat(labels).containsExactly(
                    "Traffic",
                    "Exporter",
                    "Settings",
                    "Sitemap",
                    "Findings");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void sinkCards_nestTrafficSourceSubRowsDirectlyUnderTrafficIndexRow() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordSuccess("traffic", 1);
        FileExportStats.recordSuccess("traffic", 1);
        onEdt(() -> call(panel, "refreshDashboard"));

        // Sub-rows live inline within the merged model; their position is determined entirely
        // by the alphabetical placement of the Traffic index row, with the indent on column 0
        // distinguishing them from index rows. Verify the row immediately following the
        // Traffic index row is an indented sub-row, not the next alphabetical index row.
        assertSubRowsFollowTrafficIndexRow(indexModel, indent);
        assertSubRowsFollowTrafficIndexRow(fileIndexModel, indent);
    }

    private static void assertSubRowsFollowTrafficIndexRow(DefaultTableModel model, String indent) {
        int trafficRow = -1;
        for (int row = 0; row < model.getRowCount(); row++) {
            if ("Traffic".equals(String.valueOf(model.getValueAt(row, 0)))) {
                trafficRow = row;
                break;
            }
        }
        assertThat(trafficRow).as("Traffic index row").isGreaterThanOrEqualTo(0);
        // At least one indented sub-row exists right after the Traffic row.
        assertThat(trafficRow + 1).isLessThan(model.getRowCount());
        String firstSubLabel = String.valueOf(model.getValueAt(trafficRow + 1, 0));
        assertThat(firstSubLabel).startsWith(indent);
    }

    @Test
    void sinkSections_hideAndShowBasedOnSelectedDestinations() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel fileOnlyPanel = onEdt(StatsPanel::new);
            JPanel fileChartsSection = JPanel.class.cast(get(fileOnlyPanel, "fileChartsSectionPanel"));
            JPanel openSearchChartsSection = JPanel.class.cast(get(fileOnlyPanel, "openSearchChartsSectionPanel"));
            JPanel fileSinkRow = JPanel.class.cast(get(fileOnlyPanel, "fileSinkRow"));
            JPanel openSearchSinkRow = JPanel.class.cast(get(fileOnlyPanel, "openSearchSinkRow"));
            onEdt(() -> call(fileOnlyPanel, "refreshDashboard"));
            assertThat(onEdt(fileChartsSection::isVisible)).isTrue();
            assertThat(onEdt(openSearchChartsSection::isVisible)).isFalse();
            assertThat(onEdt(fileSinkRow::isVisible)).isTrue();
            assertThat(onEdt(openSearchSinkRow::isVisible)).isFalse();

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JPanel osFileChartsSection = JPanel.class.cast(get(openSearchOnlyPanel, "fileChartsSectionPanel"));
            JPanel osOpenSearchChartsSection = JPanel.class.cast(get(openSearchOnlyPanel, "openSearchChartsSectionPanel"));
            JPanel osFileSinkRow = JPanel.class.cast(get(openSearchOnlyPanel, "fileSinkRow"));
            JPanel osOpenSearchSinkRow = JPanel.class.cast(get(openSearchOnlyPanel, "openSearchSinkRow"));
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(onEdt(osFileChartsSection::isVisible)).isFalse();
            assertThat(onEdt(osOpenSearchChartsSection::isVisible)).isTrue();
            assertThat(onEdt(osFileSinkRow::isVisible)).isFalse();
            assertThat(onEdt(osOpenSearchSinkRow::isVisible)).isTrue();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void fileSections_areOrderedBeforeOpenSearchSections() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel chartSectionsPanel = JPanel.class.cast(get(panel, "chartSectionsPanel"));
        JPanel fileChartsSection = JPanel.class.cast(get(panel, "fileChartsSectionPanel"));
        JPanel openSearchChartsSection = JPanel.class.cast(get(panel, "openSearchChartsSectionPanel"));
        JPanel memoryChartsSection = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));
        JPanel lowerPanel = JPanel.class.cast(get(panel, "lowerPanel"));
        JPanel fileSinkRow = JPanel.class.cast(get(panel, "fileSinkRow"));
        JPanel openSearchSinkRow = JPanel.class.cast(get(panel, "openSearchSinkRow"));

        // Chart ordering: file pair on top, OpenSearch pair in the middle, memory chart at
        // the bottom (heap usage is JVM-wide so it is shared regardless of which sink runs).
        assertThat(chartSectionsPanel.getComponent(0)).isSameAs(fileChartsSection);
        assertThat(chartSectionsPanel.getComponent(1)).isSameAs(openSearchChartsSection);
        assertThat(chartSectionsPanel.getComponent(2)).isSameAs(memoryChartsSection);
        // Per-sink rows mirror the chart ordering: file row precedes OpenSearch row.
        assertThat(indexOfChild(lowerPanel, fileSinkRow))
                .isLessThan(indexOfChild(lowerPanel, openSearchSinkRow));
    }

    @Test
    void byIndexTables_appendTotalRowAfterRefresh() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordSuccess("traffic", 4);
        ExportStats.recordSuccess("findings", 2);
        FileExportStats.recordSuccess("traffic", 3);
        onEdt(() -> call(panel, "refreshDashboard"));

        // Trailing Total row aggregates only the index rows, not the indented traffic-source
        // sub-rows nested under the Traffic index row. The "Last Push (ms)" / "Last Error"
        // columns are rendered as "-" because totals do not have a meaningful per-row
        // last-push or last-error attribution.
        assertTotalRowMatchesIndexRowSum(indexModel, indent);
        assertTotalRowMatchesIndexRowSum(fileIndexModel, indent);
    }

    private static void assertTotalRowMatchesIndexRowSum(DefaultTableModel model, String indent) {
        int lastRow = model.getRowCount() - 1;
        assertThat(model.getValueAt(lastRow, 0)).isEqualTo("Total");
        long total = ((Number) model.getValueAt(lastRow, 1)).longValue();
        long sumOfIndexRows = 0L;
        for (int row = 0; row < lastRow; row++) {
            String label = String.valueOf(model.getValueAt(row, 0));
            if (label.startsWith(indent)) {
                continue;
            }
            sumOfIndexRows += ((Number) model.getValueAt(row, 1)).longValue();
        }
        assertThat(total).isEqualTo(sumOfIndexRows);
    }

    @Test
    void mergedSinkCards_eachExposeOneCopyButtonForTheWholeTable() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel openSearchSinkCard = JPanel.class.cast(get(panel, "openSearchSinkCard"));
        JPanel fileSinkCard = JPanel.class.cast(get(panel, "fileSinkCard"));

        // One Copy button per merged card; the user already has full-table TSV from a single
        // click, no need for a separate per-section button now that traffic + index counts
        // share one model.
        assertThat(findByName(openSearchSinkCard, "copy.OpenSearch Counts", JButton.class))
                .as("OpenSearch Counts copy button")
                .isNotNull();
        assertThat(findByName(fileSinkCard, "copy.File Counts", JButton.class))
                .as("File Counts copy button")
                .isNotNull();
    }

    @Test
    void byIndexTable_storesUntruncatedLastErrorTextAfterRefresh() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));

        // 200-char error string is the longest message ExportStats stores verbatim (anything
        // longer is truncated at the storage layer with an ellipsis); blowing past the legacy
        // 50-char cell-truncation cap proves the table cell now holds the full string. The
        // visual width cap is purely a renderer concern - the model yields the full string so
        // per-table TSV copy returns it verbatim.
        String longError = "X".repeat(200);
        ExportStats.recordFailure("traffic", 1);
        ExportStats.recordLastError("traffic", longError);
        try {
            onEdt(() -> call(panel, "refreshDashboard"));

            String stored = null;
            for (int row = 0; row < indexModel.getRowCount(); row++) {
                if ("Traffic".equals(String.valueOf(indexModel.getValueAt(row, 0)))) {
                    // Last Error sits in the last column of the OpenSearch counts table
                    // (column index 7 with the 8-column schema).
                    stored = String.valueOf(indexModel.getValueAt(row, indexModel.getColumnCount() - 1));
                    break;
                }
            }
            assertThat(stored).as("Traffic row Last Error column").isEqualTo(longError);
        } finally {
            ExportStats.recordLastError("traffic", null);
        }
    }

    private static int indexOfChild(Container parent, Component child) {
        for (int i = 0; i < parent.getComponentCount(); i++) {
            if (parent.getComponent(i) == child) {
                return i;
            }
        }
        return -1;
    }

    @Test
    void sharedLegendPanel_movesAboveFirstVisibleHistogramGroup() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel dualPanel = onEdt(StatsPanel::new);
            JPanel dualLegend = JPanel.class.cast(get(dualPanel, "sharedLegendPanel"));
            JPanel dualFileSection = JPanel.class.cast(get(dualPanel, "fileChartsSectionPanel"));
            onEdt(() -> call(dualPanel, "refreshDashboard"));
            assertThat(dualLegend.getParent()).isSameAs(dualFileSection);
            assertThat(dualFileSection.getComponent(0)).isSameAs(dualLegend);

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JPanel osLegend = JPanel.class.cast(get(openSearchOnlyPanel, "sharedLegendPanel"));
            JPanel osSection = JPanel.class.cast(get(openSearchOnlyPanel, "openSearchChartsSectionPanel"));
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(osLegend.getParent()).isSameAs(osSection);
            assertThat(osSection.getComponent(0)).isSameAs(osLegend);
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_groupsMetricsByDestination_whenBothDestinationsEnabled() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));
            assertThat(cardsRow.getComponentCount()).isEqualTo(1);
            JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);

            assertThat(miscCard).isNotNull();

            List<String> labels = collectLabelTexts(miscCard);
            JPanel openSearchRow0 = findByName(miscCard, "miscStats.row.OpenSearch.0", JPanel.class);
            JPanel openSearchRow1 = findByName(miscCard, "miscStats.row.OpenSearch.1", JPanel.class);
            JPanel openSearchRow2 = findByName(miscCard, "miscStats.row.OpenSearch.2", JPanel.class);

            assertThat(labels).contains("Global", "OpenSearch", "Spill", "Retry", "Files");
            assertThat(labels).contains("Export Running", "Current Batch Size", "Traffic Queue Size", "Queue Drops");
            assertThat(labels).contains("Throughput (10s)");
            assertThat(labels).contains("Exported (docs · size · failures)");
            assertThat(labels).contains("Last Success");
            assertThat(labels).contains("Bulk In-Flight");
            assertThat(findByName(miscCard, "miscStats.section.Spill", JLabel.class)).isNotNull();
            assertThat(labels).contains("Queue", "Oldest Age (s)", "Enqueued / Dequeued / Dropped", "Drop Reasons");
            assertThat(labels).contains("Queue Depth", "Oldest Queued Age");
            assertThat(labels).doesNotContain("Spill Directory", "Skips by Reason", "Retry Queue Bytes (per index)");
            assertThat(openSearchRow0.getBackground()).isNotEqualTo(openSearchRow1.getBackground());
            assertThat(openSearchRow1.getBackground()).isNotEqualTo(openSearchRow2.getBackground());
            assertThat(openSearchRow0.getBackground()).isEqualTo(openSearchRow2.getBackground());
            assertThat(labels).contains("File Total Size Exported");
            assertThat(labels).contains("File Total Docs Exported");
            assertThat(labels).contains("File Total Failures");
            assertThat(labels).doesNotContain("Proxy-History Attempted/Success");

            assertThat(openSearchRow0.getBackground()).isNotEqualTo(openSearchRow1.getBackground());
            assertThat(openSearchRow0.getBackground()).isEqualTo(openSearchRow2.getBackground());
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_hidesOpenSearchSection_whenOpenSearchDestinationDisabled() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel miscCard = findByName(JPanel.class.cast(get(panel, "cardsRow")), "miscStatsCard", JPanel.class);

            assertThat(miscCard).isNotNull();
            assertThat(findByName(miscCard, "miscStats.section.Global", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Files", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.section.OpenSearch", JLabel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.section.Spill", JLabel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.section.Retry", JLabel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.row.OpenSearch.0", JPanel.class).isVisible()).isFalse();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_hidesFilesSection_whenFilesDestinationDisabled() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel miscCard = findByName(JPanel.class.cast(get(panel, "cardsRow")), "miscStatsCard", JPanel.class);

            assertThat(miscCard).isNotNull();
            assertThat(findByName(miscCard, "miscStats.section.Global", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.section.OpenSearch", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Files", JLabel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Files.0", JPanel.class).isVisible()).isFalse();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void timeLabel_appearsOnlyOnBottomVisibleHistogramGroup() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel dualPanel = onEdt(StatsPanel::new);
            JFreeChart dualFileKibChart = JFreeChart.class.cast(get(dualPanel, "fileKibChart"));
            JFreeChart dualOpenSearchKibChart = JFreeChart.class.cast(get(dualPanel, "kibChart"));
            onEdt(() -> call(dualPanel, "refreshDashboard"));
            assertThat(((DateAxis) dualFileKibChart.getXYPlot().getDomainAxis()).getLabel()).isNull();
            assertThat(((DateAxis) dualOpenSearchKibChart.getXYPlot().getDomainAxis()).getLabel()).isEqualTo("Time");

            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel fileOnlyPanel = onEdt(StatsPanel::new);
            JFreeChart fileOnlyKibChart = JFreeChart.class.cast(get(fileOnlyPanel, "fileKibChart"));
            onEdt(() -> call(fileOnlyPanel, "refreshDashboard"));
            assertThat(((DateAxis) fileOnlyKibChart.getXYPlot().getDomainAxis()).getLabel()).isEqualTo("Time");

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JFreeChart openSearchOnlyKibChart = JFreeChart.class.cast(get(openSearchOnlyPanel, "kibChart"));
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(((DateAxis) openSearchOnlyKibChart.getXYPlot().getDomainAxis()).getLabel()).isEqualTo("Time");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void formatHumanReadableBytes_usesExpectedUnitsAcrossThresholds() {
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 999L)).isEqualTo("999 B");
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 1024L)).isEqualTo("1.0 KB");
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 1024L * 1024L)).isEqualTo("1.0 MB");
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 1024L * 1024L * 1024L)).isEqualTo("1.0 GB");
    }

    @Test
    void formatBytesPairWithPercent_appendsPercentOfMax() {
        assertThat(callStatic(StatsPanel.class, "formatBytesPairWithPercent",
                512L * 1024L * 1024L, 1024L * 1024L * 1024L))
                .isEqualTo("512.0 MB / 1.0 GB (50.0%)");
        assertThat(callStatic(StatsPanel.class, "formatBytesPairWithPercent",
                8L * 1024L * 1024L * 1024L, 32L * 1024L * 1024L * 1024L))
                .isEqualTo("8.0 GB / 32.0 GB (25.0%)");
    }

    @Test
    void formatBytesPairWithPercent_omitsPercent_whenMaxUnknown() {
        String unknownMax = (String) callStatic(
                StatsPanel.class, "formatBytesPairWithPercent", 1024L, -1L);
        assertThat(unknownMax).doesNotContain("%");
        assertThat(callStatic(StatsPanel.class, "formatBytesPairWithPercent", -1L, 1024L * 1024L))
                .isEqualTo("n/a / 1.0 MB");
    }

    @Test
    void formatBytesWithPercentOf_appendsPercent_andHandlesNegatives() {
        assertThat(callStatic(StatsPanel.class, "formatBytesWithPercentOf",
                256L * 1024L * 1024L, 1024L * 1024L * 1024L))
                .isEqualTo("256.0 MB (25.0%)");
        assertThat(callStatic(StatsPanel.class, "formatBytesWithPercentOf", -1L, 1024L))
                .isEqualTo("n/a");
        assertThat(callStatic(StatsPanel.class, "formatBytesWithPercentOf", 1024L, -1L))
                .isEqualTo("1.0 KB");
    }

    @Test
    void miscStatsCard_exposesHeapCommittedAndBufferPoolRows() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel heapUsedMaxValue = JLabel.class.cast(get(panel, "heapUsedMaxValue"));
        JLabel heapCommittedValue = JLabel.class.cast(get(panel, "heapCommittedValue"));
        JLabel directBufferUsedValue = JLabel.class.cast(get(panel, "directBufferUsedValue"));
        JLabel mappedBufferUsedValue = JLabel.class.cast(get(panel, "mappedBufferUsedValue"));

        onEdt(() -> call(panel, "refreshDashboard"));

        // Heap rows are populated from a live SystemMetrics.snapshot(), so we cannot pin exact
        // values - just confirm they contain a percent annotation and a unit suffix.
        assertThat(heapUsedMaxValue.getText()).matches(".+ / .+ \\(\\d+\\.\\d+%\\)");
        assertThat(heapCommittedValue.getText()).matches(".+ \\(\\d+\\.\\d+%\\)");
        assertThat(directBufferUsedValue.getText()).isNotEmpty();
        assertThat(mappedBufferUsedValue.getText()).isNotEmpty();
    }

    @Test
    void memoryChart_isAppendedAfterPerSinkChartSections_andSamplesHeapUsedAndCommitted() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));
        JPanel chartSectionsPanel = JPanel.class.cast(get(panel, "chartSectionsPanel"));
        JPanel memoryChartSectionPanel = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));
        TimeSeries heapUsedSeries = TimeSeries.class.cast(get(panel, "heapUsedSeries"));
        TimeSeries heapCommittedSeries = TimeSeries.class.cast(get(panel, "heapCommittedSeries"));

        // Section ordering: file pair, OpenSearch pair, memory pair last (heap usage is JVM-
        // wide and unrelated to which sink is active).
        assertThat(chartSectionsPanel.getComponent(2)).isSameAs(memoryChartSectionPanel);

        // Memory chart uses MiB on the Y axis and a positive-only range type so the line
        // never dips below zero on transient negative readings.
        NumberAxis range = (NumberAxis) memoryChart.getXYPlot().getRangeAxis();
        assertThat(range.getRangeType()).isEqualTo(RangeType.POSITIVE);

        int beforeUsed = onEdt(heapUsedSeries::getItemCount);
        int beforeCommitted = onEdt(heapCommittedSeries::getItemCount);
        Thread.sleep(20L);
        onEdt(() -> call(panel, "refreshVisibleStats"));
        assertThat(onEdt(heapUsedSeries::getItemCount)).isGreaterThanOrEqualTo(beforeUsed);
        assertThat(onEdt(heapCommittedSeries::getItemCount)).isGreaterThanOrEqualTo(beforeCommitted);
    }

    @Test
    void memoryLegendPanel_sitsAtTopOfMemorySection_andHasHeapUsedAndCommittedItems() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel memoryLegendPanel = JPanel.class.cast(get(panel, "memoryLegendPanel"));
        JPanel memoryChartSectionPanel = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));

        assertThat(memoryChartSectionPanel.getComponent(0)).isSameAs(memoryLegendPanel);
        assertThat(memoryLegendPanel.getLayout()).isInstanceOf(FlowLayout.class);

        List<String> labelTexts = new ArrayList<>();
        for (Component c : memoryLegendPanel.getComponents()) {
            if (c instanceof JLabel label) {
                labelTexts.add(label.getText());
            }
        }
        assertThat(labelTexts).containsExactly("Heap Used", "Heap Committed");
    }

    @Test
    void memoryChart_seriesPaintsTrackThroughputPaletteForGreenAndYellow() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));
        XYLineAndShapeRenderer renderer =
                (XYLineAndShapeRenderer) memoryChart.getXYPlot().getRenderer();

        // The memory chart's two series adopt the throughput chart's Traffic (green) and
        // Sitemap (yellow) palette through MEMORY_SERIES_TO_STYLE.
        assertThat(renderer.getSeriesPaint(0)).isEqualTo(call(panel, "seriesLinePaint", 0));
        assertThat(renderer.getSeriesPaint(1)).isEqualTo(call(panel, "seriesLinePaint", 3));
        // The default chart style (Simple) hides shape markers on every chart, including the
        // memory chart; the Accessible-style coverage is verified separately.
        assertThat(renderer.getSeriesShapesVisible(0))
                .isEqualTo(call(panel, "seriesShapesVisible", 0));
        assertThat(renderer.getSeriesShapesVisible(1))
                .isEqualTo(call(panel, "seriesShapesVisible", 3));
    }

    @Test
    void chartStyleButton_alsoSwitchesMemoryChartRenderer() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(1, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));

            assertThat(memoryChart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);

            onEdt((Runnable) styleButton::doClick); // Smooth
            assertThat(memoryChart.getXYPlot().getRenderer()).isInstanceOf(XYSplineRenderer.class);

            onEdt((Runnable) styleButton::doClick); // Accessible
            assertThat(memoryChart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            XYLineAndShapeRenderer renderer =
                    (XYLineAndShapeRenderer) memoryChart.getXYPlot().getRenderer();
            // In Accessible style the memory chart inherits the same dashed strokes and shape
            // markers that SeriesStyle attaches to the throughput chart, so heap-used and
            // heap-committed remain distinguishable for color-blind users without color alone.
            BasicStroke stroke0 = (BasicStroke) renderer.getSeriesStroke(0);
            BasicStroke stroke1 = (BasicStroke) renderer.getSeriesStroke(1);
            assertThat(stroke0.getDashArray()).isNotNull();
            assertThat(stroke1.getDashArray()).isNotNull();
            assertThat(renderer.getSeriesShapesVisible(0)).isTrue();
            assertThat(renderer.getSeriesShapesVisible(1)).isTrue();
            assertThat(renderer.getSeriesShape(0))
                    .isEqualTo(call(panel, "seriesMarkerShape", 0));
            assertThat(renderer.getSeriesShape(1))
                    .isEqualTo(call(panel, "seriesMarkerShape", 3));
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void memoryLegendIcons_paintWithoutErrorAcrossEveryChartStyle() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel memoryLegendPanel = JPanel.class.cast(get(panel, "memoryLegendPanel"));
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));

            // Cover Simple, Smooth, and Accessible. The Accessible pass is the regression
            // guard: the icon must paint a shape marker plus dashed stroke without throwing
            // even when no chart pixels have been laid out yet.
            for (int i = 0; i < 3; i++) {
                BufferedImage canvas = new BufferedImage(32, 16, BufferedImage.TYPE_INT_ARGB);
                Graphics2D g2 = canvas.createGraphics();
                try {
                    for (Component c : memoryLegendPanel.getComponents()) {
                        if (c instanceof JLabel label && label.getIcon() != null) {
                            label.getIcon().paintIcon(label, g2, 0, 0);
                        }
                    }
                } finally {
                    g2.dispose();
                }
                onEdt((Runnable) styleButton::doClick);
            }
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_processSection_includesNewMemoryRows() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));
        JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);
        assertThat(miscCard).isNotNull();

        List<String> labels = collectLabelTexts(miscCard);
        assertThat(labels).contains("Heap Used / Max", "Heap Committed",
                "Non-Heap Used", "Direct Buffer Used", "Mapped Buffer Used");
    }

    @Test
    void refreshDashboard_updatesTotalExportedValueWithHumanReadableSize() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel exportedSummaryValue = JLabel.class.cast(get(panel, "exportedSummaryValue"));
        long beforeTotal = ExportStats.getTotalExportedBytes();

        onEdt(() -> call(panel, "refreshDashboard"));
        ExportStats.recordExportedBytes("traffic", 1024L * 1024L);

        onEdt(() -> call(panel, "refreshDashboard"));
        String expectedSize = (String) callStatic(
                StatsPanel.class,
                "formatHumanReadableBytes",
                beforeTotal + (1024L * 1024L));
        assertThat(exportedSummaryValue.getText()).contains(expectedSize);
    }

    @Test
    void refreshDashboard_updatesFileTotalExportedValueWithHumanReadableSize() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel fileTotalExportedValue = JLabel.class.cast(get(panel, "fileTotalExportedValue"));
        long beforeTotal = FileExportStats.getTotalExportedBytes();

        onEdt(() -> call(panel, "refreshDashboard"));
        FileExportStats.recordExportedBytes("traffic", 1024L * 1024L);

        onEdt(() -> call(panel, "refreshDashboard"));
        String expected = (String) callStatic(
                StatsPanel.class,
                "formatHumanReadableBytes",
                beforeTotal + (1024L * 1024L));
        assertThat(fileTotalExportedValue.getText()).isEqualTo(expected);
    }

    @Test
    void totalExportedValue_transitionsAcrossUnits_fromRecordedIndexBytes() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel exportedSummaryValue = JLabel.class.cast(get(panel, "exportedSummaryValue"));

        long beforeTotal = ExportStats.getTotalExportedBytes();

        ExportStats.recordExportedBytes("traffic", 1536L);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterKb = beforeTotal + 1536L;
        assertThat(exportedSummaryValue.getText())
                .contains((String) callStatic(StatsPanel.class, "formatHumanReadableBytes", afterKb));

        long deltaToMb = Math.max(0L, (1024L * 1024L) - afterKb);
        ExportStats.recordExportedBytes("exporter", deltaToMb);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterMb = afterKb + deltaToMb;
        String afterMbHuman = (String) callStatic(StatsPanel.class, "formatHumanReadableBytes", afterMb);
        assertThat(exportedSummaryValue.getText()).contains(afterMbHuman);
        assertThat(afterMbHuman).endsWith("MB");

        long deltaToGb = Math.max(0L, (1024L * 1024L * 1024L) - afterMb);
        ExportStats.recordExportedBytes("findings", deltaToGb);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterGb = afterMb + deltaToGb;
        String afterGbHuman = (String) callStatic(StatsPanel.class, "formatHumanReadableBytes", afterGb);
        assertThat(exportedSummaryValue.getText()).contains(afterGbHuman);
        assertThat(afterGbHuman).endsWith("GB");
    }

    @Test
    void mergedTable_countsProxyWebSocketsUnderProxyHistorySubRowAndTrafficIndex() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        onEdt(() -> call(panel, "refreshDashboard"));

        long proxyHistoryBefore = sourceTableLong(indexModel, indent + "Proxy History", 1);
        long trafficIndexBefore = sourceTableLong(indexModel, "Traffic", 1);
        long proxyHistoryFailuresBefore = sourceTableLong(indexModel, indent + "Proxy History", 5);
        long trafficIndexFailuresBefore = sourceTableLong(indexModel, "Traffic", 5);

        ExportStats.recordSuccess("traffic", 7);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", 7);
        ExportStats.recordFailure("traffic", 2);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", 2);

        onEdt(() -> call(panel, "refreshDashboard"));

        // Proxy WebSocket success/failure counts roll up into the Proxy History sub-row in
        // the merged table (TrafficRouteBucket.resolveOpenSearchSourceSuccess folds them in)
        // and into the Traffic index row.
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 1) - proxyHistoryBefore).isEqualTo(7);
        assertThat(sourceTableLong(indexModel, "Traffic", 1) - trafficIndexBefore).isEqualTo(7);
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 5) - proxyHistoryFailuresBefore).isEqualTo(2);
        assertThat(sourceTableLong(indexModel, "Traffic", 5) - trafficIndexFailuresBefore).isEqualTo(2);
    }

    @Test
    void mergedTable_subRowSumMatchesTrafficIndexAfterMixedTrafficSources() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        onEdt(() -> call(panel, "refreshDashboard"));

        long subRowSumBefore = sumSubRowsForColumn(indexModel, indent, 1);
        long trafficIndexBefore = sourceTableLong(indexModel, "Traffic", 1);
        long subRowFailureSumBefore = sumSubRowsForColumn(indexModel, indent, 5);
        long trafficIndexFailuresBefore = sourceTableLong(indexModel, "Traffic", 5);

        ExportStats.recordSuccess("traffic", 17);
        ExportStats.recordTrafficToolTypeSuccess("PROXY", 5);
        ExportStats.recordTrafficToolTypeSuccess("REPEATER", 3);
        ExportStats.recordTrafficSourceSuccess("proxy_history_snapshot", 4);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", 5);

        ExportStats.recordFailure("traffic", 4);
        ExportStats.recordTrafficSourceFailure("proxy_history_snapshot", 1);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", 3);

        onEdt(() -> call(panel, "refreshDashboard"));

        // Data integrity: the indented per-source sub-rows must sum to the same number as
        // the parent Traffic index row for both successes and failures. This is the merged
        // table's analog of the old "source-table Total == traffic-index row" invariant.
        long subRowSumAfter = sumSubRowsForColumn(indexModel, indent, 1);
        long trafficIndexAfter = sourceTableLong(indexModel, "Traffic", 1);
        long subRowFailureSumAfter = sumSubRowsForColumn(indexModel, indent, 5);
        long trafficIndexFailuresAfter = sourceTableLong(indexModel, "Traffic", 5);
        assertThat(subRowSumAfter - subRowSumBefore).isEqualTo(trafficIndexAfter - trafficIndexBefore);
        assertThat(subRowFailureSumAfter - subRowFailureSumBefore)
                .isEqualTo(trafficIndexFailuresAfter - trafficIndexFailuresBefore);
    }

    private static long sumSubRowsForColumn(DefaultTableModel model, String indent, int columnIndex) {
        long sum = 0L;
        for (int row = 0; row < model.getRowCount(); row++) {
            String label = String.valueOf(model.getValueAt(row, 0));
            if (!label.startsWith(indent)) {
                continue;
            }
            Object value = model.getValueAt(row, columnIndex);
            if (value instanceof Number number) {
                sum += number.longValue();
            }
        }
        return sum;
    }

    @Test
    void exportRunningValue_usesGreenForYesAndRedForNo() {
        boolean original = RuntimeConfig.isExportRunning();
        try {
            StatsPanel panel = onEdt(StatsPanel::new);
            JLabel exportRunningValue = JLabel.class.cast(get(panel, "exportRunningValue"));
            JLabel currentBatchSizeValue = JLabel.class.cast(get(panel, "currentBatchSizeValue"));

            onEdt(() -> {
                RuntimeConfig.setExportRunning(true);
                call(panel, "refreshDashboard");
            });
            assertThat(exportRunningValue.getText()).isEqualTo("Yes");
            assertThat(exportRunningValue.getForeground()).isEqualTo(seriesBaseColor(panel, 0));
            assertThat(exportRunningValue.getFont().isBold()).isTrue();
            assertThat(currentBatchSizeValue.getFont().isBold()).isFalse();

            onEdt(() -> {
                RuntimeConfig.setExportRunning(false);
                call(panel, "refreshDashboard");
            });
            assertThat(exportRunningValue.getText()).isEqualTo("No");
            assertThat(exportRunningValue.getForeground()).isEqualTo(seriesBaseColor(panel, 4));
            assertThat(exportRunningValue.getFont().isBold()).isTrue();
            assertThat(exportRunningValue.getFont().getStyle()).isEqualTo(Font.BOLD);
        } finally {
            onEdt(() -> RuntimeConfig.setExportRunning(original));
        }
    }

    @Test
    void chartRenderer_usesAccessibleSeriesPaintsStrokesAndMarkers() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

        JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
        onEdt((Runnable) styleButton::doClick);
        onEdt((Runnable) styleButton::doClick);
        XYLineAndShapeRenderer renderer = currentRenderer(chart);

        assertSeriesStyle(panel, renderer, 0, new float[] { 8f, 5f }, true);
        assertSeriesStyle(panel, renderer, 1, new float[] { 8f, 4f, 1.5f, 4f }, true);
        assertSeriesStyle(panel, renderer, 2, null, true);
        assertSeriesStyle(panel, renderer, 3, new float[] { 1.5f, 4f }, true);
        assertSeriesStyle(panel, renderer, 4, new float[] { 12f, 6f }, true);
    }

    @Test
    void styleButton_cyclesThroughThreeNamedChartStyles() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(1, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

            assertThat(styleButton.getText()).isEqualTo("Simple");
            assertThat(chart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            assertThat(currentRenderer(chart).getSeriesShapesVisible(0)).isFalse();

            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Smooth");
            assertThat(chart.getXYPlot().getRenderer()).isInstanceOf(XYSplineRenderer.class);
            assertThat(currentRenderer(chart).getSeriesShapesVisible(0)).isFalse();

            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Accessible");
            assertThat(chart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            assertThat(currentRenderer(chart).getSeriesShapesVisible(0)).isTrue();

            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Simple");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void smoothStyle_usesSplineRendererFillWithoutSecondaryAreaDataset() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(1, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

            XYPlot plot = chart.getXYPlot();
            assertThat(plot.getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            assertThat(styleButton.getText()).isEqualTo("Simple");
            onEdt((Runnable) styleButton::doClick);
            assertThat(plot.getRenderer()).isInstanceOf(XYSplineRenderer.class);
            XYSplineRenderer renderer = (XYSplineRenderer) plot.getRenderer();
            assertThat(renderer.getPrecision()).isEqualTo(5);
            assertThat(renderer.getFillType()).isEqualTo(XYSplineRenderer.FillType.TO_LOWER_BOUND);
            assertThat(renderer.getSeriesFillPaint(0)).isInstanceOf(call(panel, "seriesAreaPaint", 0).getClass());
            assertThat(plot.getDataset(1)).isNull();
            assertThat(plot.getRenderer(1)).isNull();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void smoothStyle_trafficAndSitemapFillsAreMoreTransparentThanExporter() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(2, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);

            GradientPaint trafficFill = GradientPaint.class.cast(call(panel, "seriesPaint", 0));
            GradientPaint exporterFill = GradientPaint.class.cast(call(panel, "seriesPaint", 1));
            GradientPaint sitemapFill = GradientPaint.class.cast(call(panel, "seriesPaint", 3));

            assertThat(trafficFill.getColor1().getAlpha()).isLessThan(exporterFill.getColor1().getAlpha());
            assertThat(sitemapFill.getColor1().getAlpha()).isLessThan(exporterFill.getColor1().getAlpha());
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void chartPanels_drawAtFullSizeWithoutJFreeChartBitmapUpscaling() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        ChartPanel docsPanel = ChartPanel.class.cast(get(panel, "openSearchDocsChartPanel"));
        ChartPanel memoryPanel = ChartPanel.class.cast(get(panel, "memoryChartPanel"));

        assertThat(docsPanel.getMinimumDrawWidth()).isZero();
        assertThat(docsPanel.getMinimumDrawHeight()).isZero();
        assertThat(docsPanel.getMaximumDrawWidth()).isEqualTo(Integer.MAX_VALUE);
        assertThat(docsPanel.getMaximumDrawHeight()).isEqualTo(Integer.MAX_VALUE);
        assertThat(memoryPanel.getMaximumDrawWidth()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void sectionHeaders_openSearchAndJvmHeapPlain_fileExportBold() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel openSearch = JLabel.class.cast(get(panel, "openSearchChartsSectionHeaderLabel"));
        JLabel fileExport = JLabel.class.cast(get(panel, "fileChartsSectionHeaderLabel"));
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));

        assertThat(openSearch.getFont().isBold()).isFalse();
        assertThat(fileExport.getFont().isBold()).isTrue();
        assertThat(memoryChart.getTitle().getFont().isBold()).isFalse();
    }

    @Test
    void charts_useMatchingStatsRangeAxisWidthSoPlotAreasAlign() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart docsChart = JFreeChart.class.cast(get(panel, "docsChart"));
        JFreeChart kibChart = JFreeChart.class.cast(get(panel, "kibChart"));
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));

        assertThat(docsChart.getXYPlot().getRangeAxis()).isInstanceOf(StatsChartRangeAxis.class);
        assertThat(rangeAxisWidth(docsChart)).isEqualTo(StatsChartRangeAxis.TOTAL_WIDTH);
        assertThat(rangeAxisWidth(kibChart)).isEqualTo(StatsChartRangeAxis.TOTAL_WIDTH);
        assertThat(rangeAxisWidth(memoryChart)).isEqualTo(StatsChartRangeAxis.TOTAL_WIDTH);
        assertThat(docsChart.getXYPlot().getFixedRangeAxisSpace()).isNull();
    }

    private static double rangeAxisWidth(JFreeChart chart) {
        return ((StatsChartRangeAxis) chart.getXYPlot().getRangeAxis()).getFixedDimension();
    }

    @Test
    void statsPanel_readsChartStyleFromRuntimeUiPreferences() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(3, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            assertThat(styleButton.getText()).isEqualTo("Accessible");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void preferredSize_growsToFitCardsAndTablesSoBottomDoesNotClip() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel chartsPanel = JPanel.class.cast(get(panel, "chartsPanel"));
        JPanel sharedLegendPanel = JPanel.class.cast(get(panel, "sharedLegendPanel"));
        JPanel memoryLegendPanel = JPanel.class.cast(get(panel, "memoryLegendPanel"));
        JPanel fileChartsSection = JPanel.class.cast(get(panel, "fileChartsSectionPanel"));
        JPanel openSearchChartsSection = JPanel.class.cast(get(panel, "openSearchChartsSectionPanel"));
        JPanel memoryChartSectionPanel = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));
        JPanel fileChartsSectionHeader = JPanel.class.cast(get(panel, "fileChartsSectionHeader"));
        JPanel openSearchChartsSectionHeader = JPanel.class.cast(get(panel, "openSearchChartsSectionHeader"));
        JPanel lowerPanel = JPanel.class.cast(get(panel, "lowerPanel"));
        JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));
        JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);
        int chartHeight = Reflect.getStaticInt(StatsPanel.class, "CHART_PANEL_HEIGHT") / 2;
        int memoryHeight = Reflect.getStaticInt(StatsPanel.class, "MEMORY_CHART_PANEL_HEIGHT");
        int padding = Reflect.getStaticInt(StatsPanel.class, "CONTENT_VERTICAL_PADDING");

        java.awt.Dimension preferred = onEdt(panel::getPreferredSize);
        int memoryLegendBudget = onEdt(memoryLegendPanel::isVisible)
                ? memoryLegendPanel.getPreferredSize().height + 4
                : 0;
        int sectionHeadersBudget =
                (onEdt(fileChartsSection::isVisible)
                        ? fileChartsSectionHeader.getPreferredSize().height + 4 : 0)
                + (onEdt(openSearchChartsSection::isVisible)
                        ? openSearchChartsSectionHeader.getPreferredSize().height + 4 : 0);
        int expectedChartsHeight = (onEdt(fileChartsSection::isVisible) ? chartHeight * 2 : 0)
                + (onEdt(openSearchChartsSection::isVisible) ? chartHeight * 2 : 0)
                + (onEdt(sharedLegendPanel::isVisible) ? sharedLegendPanel.getPreferredSize().height + 4 : 0)
                + (onEdt(memoryChartSectionPanel::isVisible) ? memoryHeight + memoryLegendBudget + 12 : 0)
                + sectionHeadersBudget;
        int requiredMinHeight = expectedChartsHeight
                + lowerPanel.getPreferredSize().height
                + padding;
        assertThat(preferred.height).isGreaterThanOrEqualTo(requiredMinHeight);
        assertThat(chartsPanel.getPreferredSize().height).isEqualTo(expectedChartsHeight);
        assertThat(cardsRow.getPreferredSize().height).isGreaterThanOrEqualTo(miscCard.getPreferredSize().height);
    }

    @Test
    void fileTablesAndCharts_updateFromFileExportStats() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        Map<String, TimeSeries> fileDocsSeriesByIndex = Map.class.cast(get(panel, "fileDocsSeriesByIndex"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        onEdt(() -> call(panel, "refreshDashboard"));
        long proxyBefore = sourceTableLong(fileIndexModel, indent + "Proxy", 1);
        long trafficBefore = sourceTableLong(fileIndexModel, "Traffic", 1);

        FileExportStats.recordSuccess("traffic", 5);
        FileExportStats.recordExportedBytes("traffic", 4096L);
        FileExportStats.recordTrafficToolTypeSuccess("PROXY", 5);
        Thread.sleep(20L);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        assertThat(sourceTableLong(fileIndexModel, indent + "Proxy", 1) - proxyBefore).isEqualTo(5);
        assertThat(sourceTableLong(fileIndexModel, "Traffic", 1) - trafficBefore).isEqualTo(5);
        assertThat(onEdt(() -> {
            TimeSeries traffic = fileDocsSeriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        })).isGreaterThan(0);
    }

    @Test
    void chartMaxPoints_coversConfiguredRollingWindowAtRefreshCadence() {
        int chartMaxPoints = Reflect.getStaticInt(StatsPanel.class, "CHART_MAX_POINTS");
        long chartWindowMs = ((Number) getStatic(StatsPanel.class, "CHART_WINDOW_MAX_MS")).longValue();
        int refreshIntervalMs = Reflect.getStaticInt(StatsPanel.class, "REFRESH_INTERVAL_MS");
        int requiredPoints = (int) (chartWindowMs / refreshIntervalMs);
        assertThat(chartMaxPoints).isGreaterThanOrEqualTo(requiredPoints);
    }

    @Test
    void mergedIndexTable_sortsNumericColumnsNumerically() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable indexTable = JTable.class.cast(get(panel, "byIndexTable"));
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));

        onEdt(() -> {
            indexModel.setRowCount(0);
            indexModel.addRow(new Object[] { "Traffic", 3242L, 0, 0L, 0L, 0L, "154083", "-" });
            indexModel.addRow(new Object[] { "Sitemap", 423L, 0, 0L, 0L, 0L, "-", "-" });
            indexModel.addRow(new Object[] { "Findings", 505L, 0, 0L, 0L, 0L, "-", "-" });
            indexTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(1, SortOrder.DESCENDING)));
        });

        // Numeric column 1 ("Docs Exported") sorts by long value, not lexicographically: with
        // descending sort the row with 3242 sits above 505 even though its first digit is "3"
        // and a string sort would place "5..." above "3...".
        List<String> indexOrder = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int i = 0; i < indexTable.getRowCount(); i++) {
                rows.add(String.valueOf(indexTable.getValueAt(i, 0)));
            }
            return rows;
        });
        assertThat(indexOrder).containsExactly("Traffic", "Findings", "Sitemap");
    }

    @Test
    void timerTick_whileExportRunning_refreshesEveryTick() {
        boolean originalRunning = RuntimeConfig.isExportRunning();
        try {
            ExportStats.resetForTests();
            RuntimeConfig.setExportRunning(true);
            StatsPanel panel = onEdt(StatsPanel::new);

            ExportStats.recordSuccess("traffic", 1);
            long before = onEdt(() -> ExportStats.getTotalSuccessCount());
            onEdt(() -> call(panel, "timerTick"));

            JLabel exportedSummaryValue = JLabel.class.cast(get(panel, "exportedSummaryValue"));
            assertThat(exportedSummaryValue.getText())
                    .startsWith(String.format(java.util.Locale.ROOT, "%,d docs", before));

            ExportStats.recordSuccess("traffic", 2);
            onEdt(() -> call(panel, "timerTick"));
            assertThat(exportedSummaryValue.getText())
                    .as("running ticks should always refresh, no skip")
                    .startsWith(String.format(
                            java.util.Locale.ROOT,
                            "%,d docs",
                            ExportStats.getTotalSuccessCount()));
        } finally {
            RuntimeConfig.setExportRunning(originalRunning);
            ExportStats.resetForTests();
        }
    }

    @Test
    void timerTick_whileIdle_skipsAllButEveryFifthTick() {
        boolean originalRunning = RuntimeConfig.isExportRunning();
        try {
            ExportStats.resetForTests();
            RuntimeConfig.setExportRunning(false);
            StatsPanel panel = onEdt(StatsPanel::new);
            JLabel exportedSummaryValue = JLabel.class.cast(get(panel, "exportedSummaryValue"));

            // Constructor's initial refresh paints 0; bump counter and confirm idle ticks skip.
            ExportStats.recordSuccess("traffic", 7);
            // First idle tick after construction: counter == 0 means it RUNS the refresh.
            onEdt(() -> call(panel, "timerTick"));
            assertThat(exportedSummaryValue.getText()).startsWith("7 docs");

            ExportStats.recordSuccess("traffic", 100);
            // Next four idle ticks should all skip (counter values 1..4 are non-zero mod 5).
            for (int i = 0; i < 4; i++) {
                onEdt(() -> call(panel, "timerTick"));
            }
            assertThat(exportedSummaryValue.getText())
                    .as("idle ticks 1..4 should not refresh, label is stale")
                    .startsWith("7 docs");

            // Fifth idle tick (counter == 5 -> 5 % 5 == 0) refreshes again.
            onEdt(() -> call(panel, "timerTick"));
            assertThat(exportedSummaryValue.getText()).startsWith("107 docs");
        } finally {
            RuntimeConfig.setExportRunning(originalRunning);
            ExportStats.resetForTests();
        }
    }

    private static void onEdt(Runnable runnable) {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
            return;
        }
        try {
            SwingUtilities.invokeAndWait(runnable);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static <T> T onEdt(Callable<T> callable) {
        if (SwingUtilities.isEventDispatchThread()) {
            try {
                return callable.call();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        AtomicReference<T> box = new AtomicReference<>();
        onEdt(() -> {
            try {
                box.set(callable.call());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        return box.get();
    }

    private static long sourceTableLong(DefaultTableModel model, String rowLabel, int columnIndex) {
        for (int row = 0; row < model.getRowCount(); row++) {
            if (rowLabel.equals(String.valueOf(model.getValueAt(row, 0)))) {
                Object value = model.getValueAt(row, columnIndex);
                if (value instanceof Number number) {
                    return number.longValue();
                }
                return Long.parseLong(String.valueOf(value));
            }
        }
        throw new AssertionError("Row not found: " + rowLabel);
    }

    private static int firstColumnPreferredWidth(JTable table) {
        return onEdt(() -> table.getColumnModel().getColumn(0).getPreferredWidth());
    }

    private static int requiredLabelColumnWidth(JTable table, String rowLabel) {
        return onEdt(() -> {
            int rowIndex = -1;
            for (int row = 0; row < table.getRowCount(); row++) {
                if (rowLabel.equals(String.valueOf(table.getValueAt(row, 0)))) {
                    rowIndex = row;
                    break;
                }
            }
            assertThat(rowIndex).isGreaterThanOrEqualTo(0);
            Component cell = table.prepareRenderer(table.getCellRenderer(rowIndex, 0), rowIndex, 0);
            Component header = table.getTableHeader()
                    .getDefaultRenderer()
                    .getTableCellRendererComponent(table, table.getColumnName(0), false, false, -1, 0);
            return Math.max(120, Math.max(header.getPreferredSize().width, cell.getPreferredSize().width) + 18);
        });
    }

    private static List<String> collectLabelTexts(Container root) {
        List<String> labels = new ArrayList<>();
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label) {
                labels.add(label.getText());
            }
            if (component instanceof Container child) {
                labels.addAll(collectLabelTexts(child));
            }
        }
        return labels;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName()) && type.isInstance(component)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static void assertSeriesStyle(
            StatsPanel panel,
            XYLineAndShapeRenderer renderer,
            int index,
            float[] expectedDashArray,
            boolean expectedShapesVisible) {
        assertThat(renderer.getSeriesPaint(index)).isEqualTo(call(panel, "seriesPaint", index));
        assertThat(renderer.getSeriesShape(index).getBounds2D())
                .isEqualTo(((Shape) call(panel, "seriesMarkerShape", index)).getBounds2D());
        assertThat(renderer.getSeriesShapesVisible(index)).isEqualTo(expectedShapesVisible);

        BasicStroke actualStroke = (BasicStroke) renderer.getSeriesStroke(index);
        BasicStroke expectedStroke = (BasicStroke) call(panel, "seriesStroke", index);
        if (expectedDashArray == null) {
            assertThat(actualStroke.getDashArray()).isNull();
        } else {
            assertThat(actualStroke.getDashArray()).containsExactly(expectedDashArray);
        }
        if (expectedStroke.getDashArray() == null) {
            assertThat(actualStroke.getDashArray()).isNull();
        } else {
            assertThat(actualStroke.getDashArray()).containsExactly(expectedStroke.getDashArray());
        }
    }

    private static XYLineAndShapeRenderer currentRenderer(JFreeChart chart) {
        return (XYLineAndShapeRenderer) chart.getXYPlot().getRenderer();
    }

    private static Color seriesBaseColor(StatsPanel panel, int index) {
        return (Color) call(panel, "seriesSolidColor", index);
    }

    private static ConfigState.State runtimeState(boolean filesEnabled, boolean openSearchEnabled) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        filesEnabled,
                        filesEnabled ? "/path/to/directory" : "",
                        filesEnabled,
                        filesEnabled,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        openSearchEnabled,
                        openSearchEnabled ? "https://opensearch.url:9200" : "",
                        "",
                        "",
                        true),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
