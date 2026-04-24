package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.ExportStats;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link StatsPanelFormatters}. Covers each output branch (empty state,
 * unit scaling) without needing a Swing harness.
 */
class StatsPanelFormattersTest {

    @BeforeEach
    void resetStats() {
        ExportStats.resetForTests();
    }

    @Test
    void formatRelativeTime_nonPositiveEpoch_returnsNever() {
        assertThat(StatsPanelFormatters.formatRelativeTime(0L, 1_000_000L)).isEqualTo("never");
        assertThat(StatsPanelFormatters.formatRelativeTime(-1L, 1_000_000L)).isEqualTo("never");
    }

    @Test
    void formatRelativeTime_subSecond_returnsZeroSecondsAgo() {
        long now = 10_000L;
        assertThat(StatsPanelFormatters.formatRelativeTime(now - 250L, now)).isEqualTo("0s ago");
    }

    @Test
    void formatRelativeTime_secondsBranch() {
        long now = 1_000_000L;
        assertThat(StatsPanelFormatters.formatRelativeTime(now - 45_000L, now)).isEqualTo("45s ago");
    }

    @Test
    void formatRelativeTime_minutesBranch() {
        long now = 10_000_000L;
        long fiveMinutesAgo = now - (5 * 60 * 1000L);
        assertThat(StatsPanelFormatters.formatRelativeTime(fiveMinutesAgo, now)).isEqualTo("5m ago");
    }

    @Test
    void formatRelativeTime_hoursBranch() {
        long now = 100_000_000L;
        long twoHoursAgo = now - (2 * 60 * 60 * 1000L);
        assertThat(StatsPanelFormatters.formatRelativeTime(twoHoursAgo, now)).isEqualTo("2h ago");
    }

    @Test
    void formatRelativeTime_daysBranch() {
        long now = 10_000_000_000L;
        long threeDaysAgo = now - (3L * 24 * 60 * 60 * 1000L);
        assertThat(StatsPanelFormatters.formatRelativeTime(threeDaysAgo, now)).isEqualTo("3d ago");
    }

    @Test
    void formatRelativeTime_futureTimestamp_clampsToZero() {
        long now = 1_000_000L;
        assertThat(StatsPanelFormatters.formatRelativeTime(now + 5_000L, now)).isEqualTo("0s ago");
    }

    @Test
    void formatOldestQueuedAges_allEmptyQueues_showsEachKeyAsDash() {
        String rendered = StatsPanelFormatters.formatOldestQueuedAges();

        assertThat(rendered)
                .contains("traffic=-")
                .contains("sitemap=-")
                .contains("findings=-");
        assertThat(rendered).doesNotMatch(".*\\d+\\.\\d+s.*");
    }

    @Test
    void formatSkipReasons_none_returnsDash() {
        assertThat(StatsPanelFormatters.formatSkipReasons()).isEqualTo("-");
    }

    @Test
    void formatSkipReasons_multipleReasons_joinsWithSpacesAndThousandsSeparators() {
        ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1_234);
        ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 5);

        String rendered = StatsPanelFormatters.formatSkipReasons();

        assertThat(rendered)
                .contains("scope=1,234")
                .contains("tool_disabled=5")
                .doesNotContain("-");
    }
}
