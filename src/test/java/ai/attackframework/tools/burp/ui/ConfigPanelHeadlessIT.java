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
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless smoke tests for ConfigPanel actions. These tests avoid layout assertions and
 * verify that clicking the buttons completes and produces a non-empty status.
 */
@Tag("integration")
class ConfigPanelHeadlessIT {

    private static final String BASE_URL = "http://opensearch.url:9200";

    @Test
    void testConnection_button_completes_and_setsStatus() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        ConfigPanel panel = onEdtAndWait(ConfigPanel::new);

        JButton testBtn = getPrivate(panel, "testConnectionButton", JButton.class);
        JTextArea statusArea = getPrivate(panel, "openSearchStatus", JTextArea.class);

        onEdtAndWait(() -> statusArea.setText(""));

        onEdtAndWait(() -> testBtn.doClick());
        awaitStatusUpdate(statusArea, 15_000);

        String text = statusArea.getText().trim();
        assertThat(text).isNotBlank();
        assertThat(text.startsWith("✖ ") || text.contains("(")).isTrue();
    }

    @Test
    void createIndexes_button_completes_and_setsStatus() throws Exception {
        var status = OpenSearchClientWrapper.testConnection(BASE_URL);
        Assumptions.assumeTrue(status.success(), "OpenSearch dev cluster not reachable");

        ConfigPanel panel = onEdtAndWait(ConfigPanel::new);

        JButton createBtn = getPrivate(panel, "createIndexesButton", JButton.class);
        JTextArea statusArea = getPrivate(panel, "openSearchStatus", JTextArea.class);

        onEdtAndWait(() -> statusArea.setText(""));

        onEdtAndWait(() -> createBtn.doClick());
        awaitStatusUpdate(statusArea, 30_000);

        String text = statusArea.getText().trim();
        assertThat(text).isNotBlank();
        assertThat(text).containsAnyOf(
                "Index created:", "Indexes created:",
                "Index already existed:", "Indexes already existed:",
                "Index failed:", "Indexes failed:"
        );
    }

    // ---------- helpers ----------

    private static <T> T getPrivate(Object target, String fieldName, Class<T> type) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return type.cast(f.get(target));
    }

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

    private static boolean isFinalStatus(String text) {
        if (text == null || text.isBlank()) return false;
        return !text.equals("Testing ...") && !text.equals("Creating indexes . . .");
    }

    /** Waits until the status area’s text becomes a non-placeholder value (no busy-waiting). */
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
            // If the worker already finished before we attached the listener
            if (isFinalStatus(area.getText())) {
                latch.countDown();
            }
        });

        boolean ok = latch.await(timeoutMs, TimeUnit.MILLISECONDS);

        onEdtAndWait(() -> area.getDocument().removeDocumentListener(ref.get()));

        if (!ok) {
            throw new AssertionError("Timed out waiting for status text update; last value: \"" + area.getText() + "\"");
        }
    }
}
