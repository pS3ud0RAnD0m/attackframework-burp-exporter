package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.ui.log.LogStore;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Memory cap enforcement.
 *
 * <p>As entries exceed the cap, old entries are trimmed and a full rebuild
 * should present only the most recent window.</p>
 */
class LogStoreCapTest {

    /**
     * With a small cap, older entries are dropped and the visible aggregate
     * contains only the most recent messages in order.
     */
    @Test
    void trimIfNeeded_enforces_cap_and_full_rebuild_reflects_recent_window() {
        int cap = 5;
        LogStore store = new LogStore(cap, (lvl, msg) -> true);

        for (int i = 1; i <= 8; i++) {
            store.ingest(LogStore.Level.DEBUG, "m" + i, LocalDateTime.now());
            if (i > cap) {
                assertTrue(store.trimIfNeeded(), "Expected trim when over cap");
            } else {
                assertFalse(store.trimIfNeeded(), "No trim at/below cap");
            }
        }

        List<LogStore.Aggregate> agg = store.buildVisibleAggregated();
        assertEquals(cap, agg.size(), "Visible window should be capped");
        assertEquals("m4", agg.getFirst().message());
        assertEquals("m8", agg.get(cap - 1).message());
    }
}
