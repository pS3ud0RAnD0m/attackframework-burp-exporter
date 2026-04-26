package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Random;

import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.allText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.field;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.onEdt;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.setText;
import static ai.attackframework.tools.burp.ui.LogPanelTestHarness.textPane;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-style integrity check for the incremental trim suffix-diff path in {@link LogPanel}.
 *
 * <p>The invariant: after any randomized ingest sequence that drives the model past its cap,
 * the document text produced by incremental trim must be byte-identical to the document text a
 * full {@code rebuildView()} would produce. Calling {@code rebuildView()} after the run is the
 * cheapest way to test this -- if the suffix-diff is correct, {@code rebuildView()} must be a
 * no-op against the document state.</p>
 *
 * <p>Random messages include a unique per-event suffix so duplicate compaction (REPLACE) is
 * not exercised here; the trim-time integrity invariant is independent of that path. A
 * separate scenario test covers the filter-merge case where REPLACE-style aggregation across
 * a trim boundary matters.</p>
 */
class LogPanelIncrementalTrimHeadlessTest {

    private static final String[] LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};
    private static final String[] MESSAGES = {
            "alpha event", "beta event", "gamma event", "delta event", "epsilon event",
            "noise frame", "background tick", "snapshot chunk", "request 200 OK",
            "response 500 ERR", "websocket frame", "config reloaded"
    };

    @Test
    void incrementalTrim_isByteIdenticalToRebuildView_noFilter() {
        runRandomized(/* seed= */ 42L, /* events= */ 7_500, /* filterText= */ "");
    }

    @Test
    void incrementalTrim_isByteIdenticalToRebuildView_withTextFilter() {
        runRandomized(/* seed= */ 7L, /* events= */ 7_500, /* filterText= */ "event");
    }

    /**
     * Filter-merge scenario: filter rejects "noise" so a "noise" entry between two equal "A"
     * entries causes the visible aggregation to merge across the trimmed boundary. The
     * suffix-diff must still produce a canonical document.
     */
    @Test
    void incrementalTrim_handlesFilterMergeAcrossTrimBoundary() {
        LogPanel p = newPanel();
        resetPanelState(p);
        setText(field(p, "log.filter.text"), "keep");

        // Force the cap quickly: emit just enough "keep" entries to fill the cap and then
        // some, interleaved with filter-rejected "noise" entries that exercise the merge
        // case where adjacent visible entries collapse after head trim.
        for (int i = 0; i < 6_000; i++) {
            p.onLog("INFO", "keep payload " + i);
            if (i % 17 == 0) p.onLog("INFO", "noise drop " + i);
            if (i % 23 == 0) p.onLog("INFO", "keep payload " + i); // intentional duplicate
        }

        String afterIncremental = allText(p);
        invokeRebuildView(p);
        String afterRebuild = allText(p);

        assertThat(afterIncremental)
                .as("incremental trim must equal full rebuild even with filter-merge boundary")
                .isEqualTo(afterRebuild);
    }

    private static void runRandomized(long seed, int eventCount, String filterText) {
        LogPanel p = newPanel();
        resetPanelState(p);
        if (!filterText.isEmpty()) {
            setText(field(p, "log.filter.text"), filterText);
        }

        Random rnd = new Random(seed);
        for (int i = 0; i < eventCount; i++) {
            String level = LEVELS[rnd.nextInt(LEVELS.length)];
            // Unique suffix avoids consecutive duplicate compaction (REPLACE), focusing this
            // run on the trim-boundary invariant.
            String message = MESSAGES[rnd.nextInt(MESSAGES.length)] + " #" + i;
            p.onLog(level, message);
        }

        String afterIncremental = allText(p);
        invokeRebuildView(p);
        String afterRebuild = allText(p);

        assertThat(afterIncremental)
                .as("incremental trim must produce a document byte-identical to a full rebuildView()")
                .isEqualTo(afterRebuild);

        String paneText = onEdt(() -> {
            JTextArea pane = textPane(p);
            try {
                return pane.getDocument().getText(0, pane.getDocument().getLength());
            } catch (BadLocationException e) {
                throw new RuntimeException(e);
            }
        });
        assertThat(paneText).isEqualTo(afterRebuild);
    }

    /**
     * Direct field-level cross-check that the in-memory mirror used by the suffix-diff stays
     * in sync with the canonical aggregated view after the cap has been hit.
     */
    @Test
    void renderedAggregates_matchesStoreVisibleAggregates_atCap() {
        LogPanel p = newPanel();
        resetPanelState(p);

        Random rnd = new Random(123L);
        for (int i = 0; i < 6_500; i++) {
            String level = LEVELS[rnd.nextInt(LEVELS.length)];
            String message = MESSAGES[rnd.nextInt(MESSAGES.length)] + " #" + i;
            p.onLog(level, message);
        }

        Object rendered = readField(p, "renderedAggregates");
        Object store = readField(p, "store");
        Object visible = invoke(store, "buildVisibleAggregated");

        assertThat(rendered).as("renderedAggregates should mirror store.buildVisibleAggregated()")
                .isEqualTo(visible);
    }

    private static void invokeRebuildView(LogPanel p) {
        onEdt(() -> {
            try {
                Method m = LogPanel.class.getDeclaredMethod("rebuildView");
                m.setAccessible(true);
                m.invoke(p);
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private static Object readField(Object target, String name) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(target);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static Object invoke(Object target, String name) {
        try {
            Method m = target.getClass().getDeclaredMethod(name);
            m.setAccessible(true);
            return m.invoke(target);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
