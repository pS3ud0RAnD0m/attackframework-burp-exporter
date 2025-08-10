package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.utils.IndexNaming;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Headless smoke for the Files sink action in ConfigPanel.
 * Verifies that clicking "Create Files" creates the expected JSON files and updates status text.
 */
@Tag("integration") // uses filesystem; no network
class ConfigPanelFileSinkHeadlessTest {

    private static final long DEFAULT_WAIT_MS = 10_000;

    @Test
    void createFilesButton_createsExpectedJsonFiles_andUpdatesStatus() throws Exception {
        Path tempDir = Files.createTempDirectory("af-burp-filesink-");
        try {
            ConfigPanel panel = onEdtAndWait(ConfigPanel::new);

            JTextField filePathField    = getPrivate(panel, "filePathField", JTextField.class);
            JCheckBox  fileSinkCheckbox = getPrivate(panel, "fileSinkCheckbox", JCheckBox.class);
            JButton    createFilesBtn   = getPrivate(panel, "createFilesButton", JButton.class);
            JTextArea  fileStatusArea   = getPrivate(panel, "fileStatus", JTextArea.class);

            onEdtAndWait(() -> {
                fileSinkCheckbox.setSelected(true);
                filePathField.setText(tempDir.toString());
                fileStatusArea.setText("");
            });

            onEdtAndWait(() -> createFilesBtn.doClick());
            awaitStatusUpdate(fileStatusArea);

            String status = fileStatusArea.getText().trim();
            assertThat(status).isNotBlank();

            // Defaults: all sources selected in the panel
            List<String> baseNames = IndexNaming.computeIndexBaseNames(
                    List.of("settings", "sitemap", "findings", "traffic"));
            List<String> jsonNames = IndexNaming.toJsonFileNames(baseNames);

            for (String json : jsonNames) {
                Path p = tempDir.resolve(json);
                assertThat(Files.exists(p))
                        .withFailMessage("Expected file was not created: %s", p)
                        .isTrue();
            }

            // Second click: most entries should report "already existed"
            onEdtAndWait(() -> fileStatusArea.setText(""));
            onEdtAndWait(() -> createFilesBtn.doClick());
            awaitStatusUpdate(fileStatusArea);
            String status2 = fileStatusArea.getText().trim();
            assertThat(status2).containsIgnoringCase("already existed");

        } finally {
            try (var walk = Files.walk(tempDir)) {
                walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                });
            }
        }
    }

    // ---------- helpers (EDT + reflection + await) ----------

    private static <T> T getPrivate(Object target, String fieldName, Class<T> type) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return type.cast(f.get(target));
    }

    private static <T> T onEdtAndWait(java.util.concurrent.Callable<T> c) throws Exception {
        AtomicReference<T> ref = new AtomicReference<>();
        AtomicReference<Exception> err = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try { ref.set(c.call()); } catch (Exception e) { err.set(e); }
        });
        if (err.get() != null) throw err.get();
        return ref.get();
    }

    private static void onEdtAndWait(Runnable r) throws Exception {
        AtomicReference<Exception> err = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try { r.run(); } catch (Exception e) { err.set(e); }
        });
        if (err.get() != null) throw err.get();
    }

    private static boolean isFinalStatus(String text) {
        return text != null && !text.isBlank();
    }

    /** Waits until the status area’s text becomes non-empty (no busy-waiting). */
    private static void awaitStatusUpdate(JTextArea area) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<DocumentListener> ref = new AtomicReference<>();

        onEdtAndWait(() -> {
            DocumentListener dl = new DocumentListener() {
                private void check() { if (isFinalStatus(area.getText())) latch.countDown(); }
                @Override public void insertUpdate(DocumentEvent e) { check(); }
                @Override public void removeUpdate(DocumentEvent e) { check(); }
                @Override public void changedUpdate(DocumentEvent e) { check(); }
            };
            ref.set(dl);
            area.getDocument().addDocumentListener(dl);
            if (isFinalStatus(area.getText())) latch.countDown();
        });

        boolean ok = latch.await(DEFAULT_WAIT_MS, TimeUnit.MILLISECONDS);
        onEdtAndWait(() -> area.getDocument().removeDocumentListener(ref.get()));
        if (!ok) throw new AssertionError("Timed out waiting for file status update; last value: \"" + area.getText() + "\"");
    }
}
