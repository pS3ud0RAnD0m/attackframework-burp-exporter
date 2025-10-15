package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.log.LogStore;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Filtering and aggregation interaction.
 *
 * <p>Hidden entries do not appear, and visible consecutive entries with the same
 * (level, message) still aggregate across hidden separators.</p>
 */
class LogStoreFilterAggregationTest {

    /**
     * Hidden entries are skipped; visible runs are aggregated as a single line
     * with an increased count.
     */
    @Test
    void filtering_skips_hidden_but_still_compacts_visible_consecutives() {
        LogStore store = new LogStore(50, (lvl, msg) -> msg != null && !msg.contains("hide"));

        store.ingest(LogStore.Level.INFO, "A", LocalDateTime.now());      // visible
        store.ingest(LogStore.Level.INFO, "hide-1", LocalDateTime.now()); // hidden
        store.ingest(LogStore.Level.INFO, "A", LocalDateTime.now());      // visible
        store.ingest(LogStore.Level.INFO, "B", LocalDateTime.now());      // visible
        store.ingest(LogStore.Level.INFO, "hide-2", LocalDateTime.now()); // hidden
        store.ingest(LogStore.Level.INFO, "B", LocalDateTime.now());      // visible

        List<LogStore.Aggregate> agg = store.buildVisibleAggregated();
        assertEquals(2, agg.size(), "Only A and B should remain after filtering");

        LogStore.Aggregate a0 = agg.get(0);
        LogStore.Aggregate a1 = agg.get(1);

        assertEquals("A", a0.message());
        assertTrue(a0.count() >= 2, "A should aggregate across hidden separators");

        assertEquals("B", a1.message());
        assertTrue(a1.count() >= 2, "B should aggregate across hidden separators");
    }
}
