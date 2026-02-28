package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StatsPanelTest {

    @Test
    void buildStatsText_containsExportStateAndSessionTotalsAndByIndex() {
        String text = StatsPanel.buildStatsText();

        assertThat(text).contains("Export state");
        assertThat(text).contains("export running:");
        assertThat(text).contains("OpenSearch URL set:");

        assertThat(text).contains("Session totals (this session)");
        assertThat(text).contains("total docs pushed:");
        assertThat(text).contains("total failures:");

        assertThat(text).contains("By index");
        assertThat(text).contains("Index");
        assertThat(text).contains("Docs pushed");
        assertThat(text).contains("Queued");
        assertThat(text).contains("Failures");
        assertThat(text).contains("Last push (ms)");
        assertThat(text).contains("Last error");

        assertThat(text).contains("traffic");
        assertThat(text).contains("tool");
        assertThat(text).contains("settings");
        assertThat(text).contains("sitemap");
        assertThat(text).contains("findings");

        assertThat(text).contains("Process total (Burp + all extensions)");
        assertThat(text).contains("Our extension (attackframework-burp-exporter)");
        assertThat(text).contains("Burp + other extensions");
        assertThat(text).contains("heap (MB)");
        assertThat(text).contains("thread count:");
    }
}
