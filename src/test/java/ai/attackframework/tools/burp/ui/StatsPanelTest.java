package ai.attackframework.tools.burp.ui;

import static ai.attackframework.tools.burp.testutils.Reflect.call;
import static ai.attackframework.tools.burp.testutils.Reflect.get;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.text.SimpleDateFormat;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.swing.SwingUtilities;

import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.RangeType;
import org.jfree.data.time.TimeSeries;

import ai.attackframework.tools.burp.utils.ExportStats;

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
