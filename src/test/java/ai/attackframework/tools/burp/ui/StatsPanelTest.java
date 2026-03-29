package ai.attackframework.tools.burp.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.Font;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import static org.assertj.core.api.Assertions.assertThat;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.RangeType;
import org.jfree.data.time.TimeSeries;
import org.junit.jupiter.api.Test;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
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
        assertThat(text).contains("tool");
        assertThat(text).contains("settings");
        assertThat(text).contains("sitemap");
        assertThat(text).contains("findings");

        assertThat(text).doesNotContain("Process total (Burp + all extensions)");
        assertThat(text).doesNotContain("Our extension (attackframework-burp-exporter)");
        assertThat(text).doesNotContain("Burp + other extensions");
        assertThat(text).doesNotContain("heap (MB)");
        assertThat(text).doesNotContain("thread count:");
    }

    @Test
    void docsChart_usesReadableTimeAxis_andPositiveWholeNumberDefaults() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart docsChart = get(panel, "docsChart");
        XYPlot plot = docsChart.getXYPlot();

        NumberAxis range = (NumberAxis) plot.getRangeAxis();
        assertThat(range.getRangeType()).isEqualTo(RangeType.POSITIVE);
        assertThat(range.getLowerBound()).isEqualTo(0.0);
        assertThat(range.getUpperBound()).isEqualTo(10.0);

        DateAxis domain = (DateAxis) plot.getDomainAxis();
        assertThat(domain.isTickLabelsVisible()).isTrue();
        assertThat(domain.getDateFormatOverride()).isInstanceOf(SimpleDateFormat.class);
        assertThat(((SimpleDateFormat) domain.getDateFormatOverride()).toPattern()).isEqualTo("HH:mm:ss");
        assertThat(domain.getTickUnit().getUnitType()).isEqualTo(DateTickUnitType.SECOND);

        JFreeChart kibChart = get(panel, "kibChart");
        NumberAxis kibRange = (NumberAxis) kibChart.getXYPlot().getRangeAxis();
        assertThat(kibRange.getRangeType()).isEqualTo(RangeType.POSITIVE);
        assertThat(kibRange.getLowerBound()).isEqualTo(0.0);
        assertThat(kibRange.getUpperBound()).isEqualTo(10.0);
    }

    @Test
    void refreshVisibleStats_addsSamplesEvenWhenPanelIsNotShowing() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        assertThat(onEdt(panel::isShowing)).isFalse();

        Map<String, TimeSeries> seriesByIndex = get(panel, "docsSeriesByIndex");
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
    void trafficBySourceTable_matchesIndexTableColumns_andMiscStatsShowsSingleStackedCard() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel sourceModel = get(panel, "trafficBySourceModel");
        DefaultTableModel indexModel = get(panel, "byIndexModel");
        JPanel cardsRow = get(panel, "cardsRow");

        assertThat(sourceModel.getColumnCount()).isEqualTo(indexModel.getColumnCount());
        assertThat(sourceModel.getColumnName(0)).isEqualTo("Source");
        assertThat(indexModel.getColumnName(0)).isEqualTo("Index");
        for (int i = 1; i < indexModel.getColumnCount(); i++) {
            assertThat(sourceModel.getColumnName(i)).isEqualTo(indexModel.getColumnName(i));
        }
        assertThat(cardsRow.getComponentCount()).isEqualTo(1);
    }

    @Test
    void byIndexTable_hasNoDefaultActiveSortKey() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = get(panel, "byIndexTable");
        RowSorter<? extends javax.swing.table.TableModel> sorter = byIndexTable.getRowSorter();
        assertThat(sorter).isNotNull();
        assertThat(sorter.getSortKeys()).isEmpty();
    }

    @Test
    void byIndexTable_remainsAlphabeticallySortedAfterRefresh() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = get(panel, "byIndexTable");

        ExportStats.recordSuccess("traffic", 11);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        List<String> visibleIndexes = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int row = 0; row < byIndexTable.getRowCount(); row++) {
                rows.add(String.valueOf(byIndexTable.getValueAt(row, 0)));
            }
            return rows;
        });
        List<String> sorted = new ArrayList<>(visibleIndexes);
        Collections.sort(sorted);
        assertThat(visibleIndexes).isEqualTo(sorted);
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
        JPanel legendPanel = (JPanel) callStatic(StatsPanel.class, "createSharedLegendPanel");
        assertThat(legendPanel.getLayout()).isInstanceOf(FlowLayout.class);
        FlowLayout layout = (FlowLayout) legendPanel.getLayout();
        assertThat(layout.getAlignment()).isEqualTo(FlowLayout.LEFT);
        Font expectedLegendFont = getStatic(StatsPanel.class, "CHART_LEGEND_FONT");

        List<String> labels = new ArrayList<>();
        for (Component component : legendPanel.getComponents()) {
            if (component instanceof JLabel label) {
                labels.add(label.getText());
                assertThat(label.getHorizontalAlignment()).isEqualTo(SwingConstants.LEFT);
                assertThat(label.getFont()).isEqualTo(expectedLegendFont);
            }
        }
        assertThat(labels).containsExactly(
                "\u2014 Traffic",
                "\u2014 Tool",
                "\u2014 Settings",
                "\u2014 Sitemap",
                "\u2014 Findings");
    }

    @Test
    void tablesRow_placesTrafficByIndexBeforeTrafficBySource() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel tablesRow = get(panel, "tablesRow");
        JTable byIndexTable = get(panel, "byIndexTable");
        JTable trafficBySourceTable = get(panel, "trafficBySourceTable");

        assertThat(findDescendant((Container) tablesRow.getComponent(0), JTable.class)).isSameAs(byIndexTable);
        assertThat(findDescendant((Container) tablesRow.getComponent(1), JTable.class)).isSameAs(trafficBySourceTable);
    }

    @Test
    void sinkSections_hideAndShowBasedOnSelectedDestinations() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel fileOnlyPanel = onEdt(StatsPanel::new);
            JPanel fileChartsSection = get(fileOnlyPanel, "fileChartsSectionPanel");
            JPanel openSearchChartsSection = get(fileOnlyPanel, "openSearchChartsSectionPanel");
            JPanel fileTablesRow = get(fileOnlyPanel, "fileTablesRow");
            JPanel tablesRow = get(fileOnlyPanel, "tablesRow");
            onEdt(() -> call(fileOnlyPanel, "refreshDashboard"));
            assertThat(onEdt(fileChartsSection::isVisible)).isTrue();
            assertThat(onEdt(openSearchChartsSection::isVisible)).isFalse();
            assertThat(onEdt(fileTablesRow::isVisible)).isTrue();
            assertThat(onEdt(tablesRow::isVisible)).isFalse();

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JPanel osFileChartsSection = get(openSearchOnlyPanel, "fileChartsSectionPanel");
            JPanel osOpenSearchChartsSection = get(openSearchOnlyPanel, "openSearchChartsSectionPanel");
            JPanel osFileTablesRow = get(openSearchOnlyPanel, "fileTablesRow");
            JPanel osTablesRow = get(openSearchOnlyPanel, "tablesRow");
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(onEdt(osFileChartsSection::isVisible)).isFalse();
            assertThat(onEdt(osOpenSearchChartsSection::isVisible)).isTrue();
            assertThat(onEdt(osFileTablesRow::isVisible)).isFalse();
            assertThat(onEdt(osTablesRow::isVisible)).isTrue();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void fileSections_areOrderedBeforeOpenSearchSections() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel chartSectionsPanel = get(panel, "chartSectionsPanel");
        JPanel fileChartsSection = get(panel, "fileChartsSectionPanel");
        JPanel openSearchChartsSection = get(panel, "openSearchChartsSectionPanel");
        JPanel fileTablesRow = get(panel, "fileTablesRow");
        JPanel tablesRow = get(panel, "tablesRow");

        assertThat(chartSectionsPanel.getComponent(0)).isSameAs(fileChartsSection);
        assertThat(chartSectionsPanel.getComponent(1)).isSameAs(openSearchChartsSection);
        assertThat(findDescendant((Container) fileTablesRow.getComponent(0), JTable.class))
                .isSameAs(get(panel, "fileByIndexTable"));
        assertThat(findDescendant((Container) fileTablesRow.getComponent(1), JTable.class))
                .isSameAs(get(panel, "fileTrafficBySourceTable"));
        assertThat(findDescendant((Container) tablesRow.getComponent(0), JTable.class))
                .isSameAs(get(panel, "byIndexTable"));
        assertThat(findDescendant((Container) tablesRow.getComponent(1), JTable.class))
                .isSameAs(get(panel, "trafficBySourceTable"));
    }

    @Test
    void miscStatsCard_groupsMetricsByDestinationAndKeepsFileSectionVisible() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel cardsRow = get(panel, "cardsRow");
        assertThat(cardsRow.getComponentCount()).isEqualTo(1);
        JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);

        assertThat(miscCard).isNotNull();

        List<String> labels = collectLabelTexts(miscCard);
        JPanel openSearchRow0 = findByName(miscCard, "miscStats.row.OpenSearch.0", JPanel.class);
        JPanel openSearchRow1 = findByName(miscCard, "miscStats.row.OpenSearch.1", JPanel.class);
        JPanel openSearchRow2 = findByName(miscCard, "miscStats.row.OpenSearch.2", JPanel.class);

        assertThat(labels).contains("Global", "OpenSearch", "Files");
        assertThat(labels).contains("Export Running", "Current Batch Size", "Traffic Queue Size", "Queue Drops");
        assertThat(labels).contains("Spill Queue Docs");
        assertThat(labels).contains("Spill Oldest Age (s)");
        assertThat(labels).contains("Spill Enq/Deq/Drops");
        assertThat(labels).contains("Drop Reasons (Spill/Queue/Requeue/Retention)");
        assertThat(labels).contains("Spill Directory");
        assertThat(labels).contains("OpenSearch Throughput (Last 10s)");
        assertThat(labels).contains("OpenSearch Total Size Exported");
        assertThat(labels).contains("OpenSearch Total Docs Exported");
        assertThat(labels).contains("OpenSearch Total Failures");
        assertThat(labels).contains("File Total Size Exported");
        assertThat(labels).contains("File Total Docs Exported");
        assertThat(labels).contains("File Total Failures");
        assertThat(labels).doesNotContain("Proxy-History Attempted/Success");

        assertThat(openSearchRow0.getBackground()).isNotEqualTo(openSearchRow1.getBackground());
        assertThat(openSearchRow0.getBackground()).isEqualTo(openSearchRow2.getBackground());
    }

    @Test
    void timeLabel_appearsOnlyOnBottomVisibleHistogramGroup() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel dualPanel = onEdt(StatsPanel::new);
            JFreeChart dualFileKibChart = get(dualPanel, "fileKibChart");
            JFreeChart dualOpenSearchKibChart = get(dualPanel, "kibChart");
            onEdt(() -> call(dualPanel, "refreshDashboard"));
            assertThat(((DateAxis) dualFileKibChart.getXYPlot().getDomainAxis()).getLabel()).isNull();
            assertThat(((DateAxis) dualOpenSearchKibChart.getXYPlot().getDomainAxis()).getLabel()).isEqualTo("Time");

            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel fileOnlyPanel = onEdt(StatsPanel::new);
            JFreeChart fileOnlyKibChart = get(fileOnlyPanel, "fileKibChart");
            onEdt(() -> call(fileOnlyPanel, "refreshDashboard"));
            assertThat(((DateAxis) fileOnlyKibChart.getXYPlot().getDomainAxis()).getLabel()).isEqualTo("Time");

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JFreeChart openSearchOnlyKibChart = get(openSearchOnlyPanel, "kibChart");
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
    void refreshDashboard_updatesTotalExportedValueWithHumanReadableSize() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel totalExportedValue = get(panel, "totalExportedValue");
        long beforeTotal = ExportStats.getTotalExportedBytes();

        onEdt(() -> call(panel, "refreshDashboard"));
        ExportStats.recordExportedBytes("traffic", 1024L * 1024L);

        onEdt(() -> call(panel, "refreshDashboard"));
        String expected = (String) callStatic(
                StatsPanel.class,
                "formatHumanReadableBytes",
                beforeTotal + (1024L * 1024L));
        assertThat(totalExportedValue.getText()).isEqualTo(expected);
    }

    @Test
    void refreshDashboard_updatesFileTotalExportedValueWithHumanReadableSize() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel fileTotalExportedValue = get(panel, "fileTotalExportedValue");
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
        JLabel totalExportedValue = get(panel, "totalExportedValue");

        long beforeTotal = ExportStats.getTotalExportedBytes();

        ExportStats.recordExportedBytes("traffic", 1536L);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterKb = beforeTotal + 1536L;
        assertThat(totalExportedValue.getText())
                .isEqualTo(callStatic(StatsPanel.class, "formatHumanReadableBytes", afterKb));

        long deltaToMb = Math.max(0L, (1024L * 1024L) - afterKb);
        ExportStats.recordExportedBytes("tool", deltaToMb);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterMb = afterKb + deltaToMb;
        assertThat(totalExportedValue.getText())
                .isEqualTo(callStatic(StatsPanel.class, "formatHumanReadableBytes", afterMb));
        assertThat(totalExportedValue.getText()).endsWith("MB");

        long deltaToGb = Math.max(0L, (1024L * 1024L * 1024L) - afterMb);
        ExportStats.recordExportedBytes("findings", deltaToGb);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterGb = afterMb + deltaToGb;
        assertThat(totalExportedValue.getText())
                .isEqualTo(callStatic(StatsPanel.class, "formatHumanReadableBytes", afterGb));
        assertThat(totalExportedValue.getText()).endsWith("GB");
    }

    @Test
    void trafficBySourceTable_countsProxyWebSocketsUnderProxyHistoryAndTotal() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel sourceModel = get(panel, "trafficBySourceModel");
        DefaultTableModel indexModel = get(panel, "byIndexModel");

        onEdt(() -> call(panel, "refreshDashboard"));

        long proxyHistoryBefore = sourceTableLong(sourceModel, "Proxy History", 1);
        long sourceTotalBefore = sourceTableLong(sourceModel, "Total", 1);
        long trafficIndexBefore = sourceTableLong(indexModel, "Traffic", 1);
        long proxyHistoryFailuresBefore = sourceTableLong(sourceModel, "Proxy History", 4);
        long sourceTotalFailuresBefore = sourceTableLong(sourceModel, "Total", 4);
        long trafficIndexFailuresBefore = sourceTableLong(indexModel, "Traffic", 4);

        ExportStats.recordSuccess("traffic", 7);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", 7);
        ExportStats.recordFailure("traffic", 2);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", 2);

        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(sourceTableLong(sourceModel, "Proxy History", 1) - proxyHistoryBefore).isEqualTo(7);
        assertThat(sourceTableLong(sourceModel, "Total", 1) - sourceTotalBefore).isEqualTo(7);
        assertThat(sourceTableLong(indexModel, "Traffic", 1) - trafficIndexBefore).isEqualTo(7);
        assertThat(sourceTableLong(sourceModel, "Proxy History", 4) - proxyHistoryFailuresBefore).isEqualTo(2);
        assertThat(sourceTableLong(sourceModel, "Total", 4) - sourceTotalFailuresBefore).isEqualTo(2);
        assertThat(sourceTableLong(indexModel, "Traffic", 4) - trafficIndexFailuresBefore).isEqualTo(2);
    }

    @Test
    void trafficBySourceTotal_matchesTrafficIndexAfterMixedTrafficSources() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel sourceModel = get(panel, "trafficBySourceModel");
        DefaultTableModel indexModel = get(panel, "byIndexModel");

        onEdt(() -> call(panel, "refreshDashboard"));

        long sourceTotalBefore = sourceTableLong(sourceModel, "Total", 1);
        long trafficIndexBefore = sourceTableLong(indexModel, "Traffic", 1);
        long sourceTotalFailuresBefore = sourceTableLong(sourceModel, "Total", 4);
        long trafficIndexFailuresBefore = sourceTableLong(indexModel, "Traffic", 4);

        ExportStats.recordSuccess("traffic", 17);
        ExportStats.recordTrafficToolTypeCaptured("PROXY", 5);
        ExportStats.recordTrafficToolTypeCaptured("REPEATER", 3);
        ExportStats.recordTrafficSourceSuccess("proxy_history_snapshot", 4);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", 5);

        ExportStats.recordFailure("traffic", 4);
        ExportStats.recordTrafficSourceFailure("proxy_history_snapshot", 1);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", 3);

        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(sourceTableLong(sourceModel, "Total", 1) - sourceTotalBefore).isEqualTo(17);
        assertThat(sourceTableLong(indexModel, "Traffic", 1) - trafficIndexBefore).isEqualTo(17);
        assertThat(sourceTableLong(sourceModel, "Total", 4) - sourceTotalFailuresBefore).isEqualTo(4);
        assertThat(sourceTableLong(indexModel, "Traffic", 4) - trafficIndexFailuresBefore).isEqualTo(4);
    }

    @Test
    void exportRunningValue_usesGreenForYesAndRedForNo() {
        boolean original = RuntimeConfig.isExportRunning();
        try {
            StatsPanel panel = onEdt(StatsPanel::new);
            JLabel exportRunningValue = get(panel, "exportRunningValue");
            JLabel currentBatchSizeValue = get(panel, "currentBatchSizeValue");
            Color[] seriesColors = getStatic(StatsPanel.class, "SERIES_COLORS");

            onEdt(() -> {
                RuntimeConfig.setExportRunning(true);
                call(panel, "refreshDashboard");
            });
            assertThat(exportRunningValue.getText()).isEqualTo("Yes");
            assertThat(exportRunningValue.getForeground()).isEqualTo(seriesColors[1]);
            assertThat(exportRunningValue.getFont().isBold()).isTrue();
            assertThat(currentBatchSizeValue.getFont().isBold()).isFalse();

            onEdt(() -> {
                RuntimeConfig.setExportRunning(false);
                call(panel, "refreshDashboard");
            });
            assertThat(exportRunningValue.getText()).isEqualTo("No");
            assertThat(exportRunningValue.getForeground()).isEqualTo(seriesColors[4]);
            assertThat(exportRunningValue.getFont().isBold()).isTrue();
            assertThat(exportRunningValue.getFont().getStyle()).isEqualTo(Font.BOLD);
        } finally {
            onEdt(() -> RuntimeConfig.setExportRunning(original));
        }
    }

    @Test
    void preferredSize_growsToFitCardsAndTablesSoBottomDoesNotClip() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel chartsPanel = get(panel, "chartsPanel");
        JPanel sharedLegendPanel = get(panel, "sharedLegendPanel");
        JPanel fileChartsSection = get(panel, "fileChartsSectionPanel");
        JPanel openSearchChartsSection = get(panel, "openSearchChartsSectionPanel");
        JPanel lowerPanel = get(panel, "lowerPanel");
        JPanel cardsRow = get(panel, "cardsRow");
        JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);
        int chartHeight = ((Integer) getStatic(StatsPanel.class, "CHART_PANEL_HEIGHT")) / 2;
        int padding = getStatic(StatsPanel.class, "CONTENT_VERTICAL_PADDING");

        java.awt.Dimension preferred = onEdt(panel::getPreferredSize);
        int expectedChartsHeight = (onEdt(fileChartsSection::isVisible) ? chartHeight * 2 : 0)
                + (onEdt(openSearchChartsSection::isVisible) ? chartHeight * 2 : 0)
                + (onEdt(sharedLegendPanel::isVisible) ? sharedLegendPanel.getPreferredSize().height + 4 : 0);
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
        DefaultTableModel fileSourceModel = get(panel, "fileTrafficBySourceModel");
        DefaultTableModel fileIndexModel = get(panel, "fileByIndexModel");
        Map<String, TimeSeries> fileDocsSeriesByIndex = get(panel, "fileDocsSeriesByIndex");

        onEdt(() -> call(panel, "refreshDashboard"));
        long proxyBefore = sourceTableLong(fileSourceModel, "Proxy", 1);
        long trafficBefore = sourceTableLong(fileIndexModel, "Traffic", 1);

        FileExportStats.recordSuccess("traffic", 5);
        FileExportStats.recordExportedBytes("traffic", 4096L);
        FileExportStats.recordTrafficToolTypeCaptured("PROXY", 5);
        Thread.sleep(20L);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        assertThat(sourceTableLong(fileSourceModel, "Proxy", 1) - proxyBefore).isEqualTo(5);
        assertThat(sourceTableLong(fileIndexModel, "Traffic", 1) - trafficBefore).isEqualTo(5);
        assertThat(onEdt(() -> {
            TimeSeries traffic = fileDocsSeriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        })).isGreaterThan(0);
    }

    @Test
    void chartMaxPoints_coversConfiguredRollingWindowAtRefreshCadence() {
        int chartMaxPoints = getStatic(StatsPanel.class, "CHART_MAX_POINTS");
        long chartWindowMs = getStatic(StatsPanel.class, "CHART_WINDOW_MAX_MS");
        int refreshIntervalMs = getStatic(StatsPanel.class, "REFRESH_INTERVAL_MS");
        int requiredPoints = (int) (chartWindowMs / refreshIntervalMs);
        assertThat(chartMaxPoints).isGreaterThanOrEqualTo(requiredPoints);
    }

    @Test
    void sourceAndIndexTables_sortNumericColumnsNumerically() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable sourceTable = get(panel, "trafficBySourceTable");
        JTable indexTable = get(panel, "byIndexTable");
        DefaultTableModel sourceModel = get(panel, "trafficBySourceModel");
        DefaultTableModel indexModel = get(panel, "byIndexModel");

        onEdt(() -> {
            sourceModel.setRowCount(0);
            sourceModel.addRow(new Object[] { "Proxy", "58", "-", "-", "0", "-", "-" });
            sourceModel.addRow(new Object[] { "Total", "4616", "-", "-", "0", "-", "-" });
            sourceModel.addRow(new Object[] { "Scanner", "1316", "-", "-", "0", "-", "-" });
            sourceTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(1, SortOrder.DESCENDING)));

            indexModel.setRowCount(0);
            indexModel.addRow(new Object[] { "Traffic", 3242L, 0, 0L, 0L, "154083", "-" });
            indexModel.addRow(new Object[] { "Sitemap", 423L, 0, 0L, 0L, "-", "-" });
            indexModel.addRow(new Object[] { "Findings", 505L, 0, 0L, 0L, "-", "-" });
            indexTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(1, SortOrder.DESCENDING)));
        });

        List<String> sourceOrder = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int i = 0; i < sourceTable.getRowCount(); i++) {
                rows.add(String.valueOf(sourceTable.getValueAt(i, 0)));
            }
            return rows;
        });
        assertThat(sourceOrder).containsExactly("Total", "Scanner", "Proxy");

        List<String> indexOrder = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int i = 0; i < indexTable.getRowCount(); i++) {
                rows.add(String.valueOf(indexTable.getValueAt(i, 0)));
            }
            return rows;
        });
        assertThat(indexOrder).containsExactly("Traffic", "Findings", "Sitemap");
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
        final Object[] box = new Object[1];
        onEdt(() -> {
            try {
                box[0] = callable.call();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        @SuppressWarnings("unchecked")
        T value = (T) box[0];
        return value;
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

    private static <T extends Component> T findDescendant(Container root, Class<T> type) {
        if (type.isInstance(root)) {
            return type.cast(root);
        }
        for (Component component : root.getComponents()) {
            if (component instanceof Container child) {
                T found = findDescendant(child, type);
                if (found != null) {
                    return found;
                }
            } else if (type.isInstance(component)) {
                return type.cast(component);
            }
        }
        return null;
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
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_BYTES,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        openSearchEnabled,
                        openSearchEnabled ? "https://opensearch.url:9200" : "",
                        "",
                        "",
                        true),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("PROXY"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
