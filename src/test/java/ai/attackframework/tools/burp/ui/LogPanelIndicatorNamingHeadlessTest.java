package ai.attackframework.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless test that asserts {@link LogPanel} exposes stable component names
 * for regex indicator labels. Tests that exercise indicator logic use these names
 * to locate components rather than reflecting private fields.
 */
class LogPanelIndicatorNamingHeadlessTest {

    @Test
    void indicator_labels_have_stable_names() {
        LogPanel panel = new LogPanel();

        JLabel filter = findLabelByName(panel, "log.filter.regex.indicator");
        JLabel search = findLabelByName(panel, "log.search.regex.indicator");

        assertThat(filter).as("filter indicator exists with stable name").isNotNull();
        assertThat(search).as("search indicator exists with stable name").isNotNull();
    }

    /* ----------------------------- helpers ----------------------------- */

    /**
     * Breadth-first search for a {@link JLabel} by component name.
     *
     * @param root container to search
     * @param name expected component name
     * @return the first matching label
     * @throws AssertionError if not found
     */
    private static JLabel findLabelByName(Container root, String name) {
        Deque<Component> q = new ArrayDeque<>();
        q.add(root);
        while (!q.isEmpty()) {
            Component c = q.removeFirst();
            if (c instanceof JLabel lbl && name.equals(lbl.getName())) {
                return lbl;
            }
            if (c instanceof Container cont) {
                Collections.addAll(q, cont.getComponents());
            }
        }
        throw new AssertionError("Label not found: name=" + name);
    }
}
