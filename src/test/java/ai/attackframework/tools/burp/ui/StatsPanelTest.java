package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

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
}
