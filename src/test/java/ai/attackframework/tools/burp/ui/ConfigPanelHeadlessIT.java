package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless smoke tests for ConfigPanel actions.
 *
 * Intent:
 * - Clicking “Test Connection” completes and writes a non-empty status.
 * - Clicking “Create Indexes” completes and writes a status describing the outcome.
 *
 * Approach:
 * - Assume an OpenSearch dev cluster is reachable before running each test.
 * - Access private Swing fields with the shared Reflection test helper to keep production visibility minimal.
 * - Await asynchronous completion using a DocumentListener + CountDownLatch (no sleeps).
 * - Run UI mutations on the EDT via onEdtAndWait helpers.
 */
@Tag("integration")
class ConfigPanelHeadlessIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void testConnection_button_completes_and_setsStatus() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        ConfigPanel panel = onEdtAndWait(ConfigPanel::new);

        JButton testBtn   = get(panel, "testConnectionButton");
        JTextArea statusA = get(panel, "openSearchStatus");

        onEdtAndWait(() -> statusA.setText(""));

        // Use a lambda to disambiguate JButton#doClick() vs doClick(int)
        onEdtAndWait(() -> testBtn.doClick());
        awaitStatusUpdate(statusA, 15_000);

        String text = statusA.getText().trim();
        assertThat(text).isNotBlank();
        // Success example: "OpenSearch ... (OpenSearch vX.Y.Z)"
        // Failure example: "✖ <message>"
        assertThat(text.startsWith("✖ ") || text.contains("(")).isTrue();
    }

    @Test
    void createIndexes_button_completes_and_setsStatus() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        ConfigPanel panel = onEdtAndWait(ConfigPanel::new);

        JButton createBtn = get(panel, "createIndexesButton");
        JTextArea statusA = get(panel, "openSearchStatus");

        onEdtAndWait(() -> statusA.setText(""));

        // Use a lambda to disambiguate JButton#doClick() vs doClick(int)
        onEdtAndWait(() -> createBtn.doClick());
        awaitStatusUpdate(statusA, 30_000);

        String text = statusA.getText().trim();
        assertThat(text).isNotBlank();
        assertThat(text).containsAnyOf(
                "Index created:", "Indexes created:",
                "Index already existed:", "Indexes already existed:",
                "Index failed:", "Indexes failed:"
        );
    }

    // ---------- helpers ----------

    /**
     * Creates a value on the EDT and returns it, propagating any exception.
     */
    private static <T> T onEdtAndWait(java.util.concurrent.Callable<T> c) throws Exception {
        AtomicReference<T> ref = new AtomicReference<>();
        AtomicReference<Exception> err = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                ref.set(c.call());
            } catch (Exception e) {
                err.set(e);
            }
        });
        if (err.get() != null) throw err.get();
        return ref.get();
    }

    /**
     * Runs a task on the EDT and blocks until completion, propagating any exception.
     */
    private static void onEdtAndWait(Runnable r) throws Exception {
        AtomicReference<Exception> err = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                r.run();
            } catch (Exception e) {
                err.set(e);
            }
        });
        if (err.get() != null) throw err.get();
    }

    /**
     * Returns true when the status text is a non-placeholder value (i.e., not a transient “busy” message).
     */
    private static boolean isFinalStatus(String text) {
        if (text == null || text.isBlank()) return false;
        return !text.equals("Testing ...") && !text.equals("Creating indexes . . .");
    }

    /**
     * Waits until the status area’s text becomes a non-placeholder value or times out.
     * Uses a listener to react immediately when the worker updates the document.
     */
    private static void awaitStatusUpdate(JTextArea area, long timeoutMs) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<DocumentListener> ref = new AtomicReference<>();

        onEdtAndWait(() -> {
            DocumentListener dl = new DocumentListener() {
                private void check() {
                    String t = area.getText();
                    if (isFinalStatus(t)) {
                        latch.countDown();
                    }
                }
                @Override public void insertUpdate(DocumentEvent e) { check(); }
                @Override public void removeUpdate(DocumentEvent e) { check(); }
                @Override public void changedUpdate(DocumentEvent e) { check(); }
            };
            ref.set(dl);
            area.getDocument().addDocumentListener(dl);
            // Handle the case where the worker completed before the listener was attached.
            if (isFinalStatus(area.getText())) {
                latch.countDown();
            }
        });

        boolean ok = latch.await(timeoutMs, TimeUnit.MILLISECONDS);

        onEdtAndWait(() -> {
            DocumentListener dl = ref.get();
            if (dl != null) {
                area.getDocument().removeDocumentListener(dl);
            }
        });

        if (!ok) {
            throw new AssertionError(
                    "Timed out waiting for status text update; last value: \"" + area.getText() + "\""
            );
        }
    }
}
