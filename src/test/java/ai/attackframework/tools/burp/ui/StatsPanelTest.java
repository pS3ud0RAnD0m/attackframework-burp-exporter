package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static ai.attackframework.tools.burp.testutils.Reflect.getStatic;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.text.SimpleDateFormat;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.awt.Component;
import java.awt.FlowLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.RowSorter;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.JTable;
import javax.swing.SortOrder;
import javax.swing.table.DefaultTableModel;

import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.RangeType;
import org.jfree.data.time.TimeSeries;

import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.Logger;

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
        assertThat(text).contains("total docs pushed:");
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
        assertThat(text).contains("Docs pushed");
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
    void trafficBySourceTable_matchesIndexTableColumns_andCardsOnlyShowExportState() {
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
    void byIndexTable_defaultsToAscendingIndexSort() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = get(panel, "byIndexTable");
        RowSorter<? extends javax.swing.table.TableModel> sorter = byIndexTable.getRowSorter();
        assertThat(sorter).isNotNull();
        assertThat(sorter.getSortKeys()).isNotEmpty();
        RowSorter.SortKey firstKey = sorter.getSortKeys().get(0);
        assertThat(firstKey.getColumn()).isEqualTo(0);
        assertThat(firstKey.getSortOrder()).isEqualTo(SortOrder.ASCENDING);
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

        List<String> labels = new ArrayList<>();
        for (Component component : legendPanel.getComponents()) {
            if (component instanceof JLabel label) {
                labels.add(label.getText());
                assertThat(label.getHorizontalAlignment()).isEqualTo(SwingConstants.LEFT);
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
    void miscStatsCard_doesNotIncludeProxyHistoryAttemptedSuccess() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel cardsRow = get(panel, "cardsRow");
        assertThat(cardsRow.getComponentCount()).isEqualTo(1);
        JPanel miscCard = (JPanel) cardsRow.getComponent(0);

        List<String> labels = new ArrayList<>();
        for (Component component : miscCard.getComponents()) {
            if (component instanceof JLabel label) {
                labels.add(label.getText());
            }
        }
        assertThat(labels).contains("Throughput (Last 10s)");
        assertThat(labels).contains("Spill Queue Docs");
        assertThat(labels).contains("Spill Oldest Age (s)");
        assertThat(labels).contains("Spill Enq/Deq/Drops");
        assertThat(labels).contains("Drop Reasons (Spill/Queue/Requeue/Retention)");
        assertThat(labels).contains("Spill Directory");
        assertThat(labels).contains("Total Docs Pushed");
        assertThat(labels).contains("Total Failures");
        assertThat(labels).doesNotContain("Proxy-History Attempted/Success");
    }

    @Test
    void preferredSize_growsToFitCardsAndTablesSoBottomDoesNotClip() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel tablesRow = get(panel, "tablesRow");
        JPanel cardsRow = get(panel, "cardsRow");
        int chartHeight = getStatic(StatsPanel.class, "CHART_PANEL_HEIGHT");
        int padding = getStatic(StatsPanel.class, "CONTENT_VERTICAL_PADDING");

        java.awt.Dimension preferred = onEdt(panel::getPreferredSize);
        int requiredMinHeight = chartHeight + tablesRow.getPreferredSize().height + cardsRow.getPreferredSize().height + padding;
        assertThat(preferred.height).isGreaterThanOrEqualTo(requiredMinHeight);
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
}
