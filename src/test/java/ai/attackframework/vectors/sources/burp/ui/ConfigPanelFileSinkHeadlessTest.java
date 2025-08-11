package ai.attackframework.vectors.sources.burp.ui;

import ai.attackframework.vectors.sources.burp.utils.IndexNaming;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("headless")
public class ConfigPanelFileSinkHeadlessTest {

    private static final long DEFAULT_WAIT_MS = 8000;

    @Test
    void createFilesButton_createsExpectedJsonFiles_andUpdatesStatus() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        // Build the list of expected JSON filenames and pre-create them
        // so the final status must include "already existed".
        List<String> sources = new ArrayList<>();
        sources.add("settings");
        sources.add("sitemap");
        sources.add("findings");
        sources.add("traffic");

        List<String> baseNames = IndexNaming.computeIndexBaseNames(sources);
        List<String> jsonNames = IndexNaming.toJsonFileNames(baseNames);

        Path tmpDir = Files.createTempDirectory("af-burp-filesink-");
        for (String name : jsonNames) {
            Files.createFile(tmpDir.resolve(name));
        }

        // Reflect private UI fields we need to drive the interaction.
        JTextField pathField   = (JTextField) getPrivate(panel, "filePathField");
        JButton createBtn      = (JButton) getPrivate(panel, "createFilesButton");
        JTextArea statusArea   = (JTextArea) getPrivate(panel, "fileStatus");

        // Set path and click on the EDT.
        onEdtAndWait(() -> pathField.setText(tmpDir.toString()));
        onEdtAndWait(createBtn::doClick);

        // Wait for the asynchronous worker to post the final status.
        waitForFinalFileStatus(statusArea);

        String status = statusArea.getText().toLowerCase(Locale.ROOT);
        assertTrue(status.contains("already existed"),
                "Expecting final status to mention already existed; actual:\n" + statusArea.getText());
    }

    /** Reflects a private field by name. */
    private static Object getPrivate(Object target, String fieldName) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(target);
    }

    /** Runs the given runnable on the EDT and blocks until complete. */
    private static void onEdtAndWait(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    /** True iff the status text represents a final (post-worker) state. */
    private static boolean isFinalStatus(String s) {
        if (s == null) return false;
        String t = s.toLowerCase(Locale.ROOT);
        return t.contains("file created:")
                || t.contains("files created:")
                || t.contains("file already existed:")
                || t.contains("files already existed:")
                || t.contains("file creation failed:")
                || t.contains("file creations failed:")
                || t.startsWith("file creation error:");
    }

    /**
     * Waits until the file status text reaches a final state or times out.
     * Uses a DocumentListener to react as soon as the SwingWorker completes.
     */
    private static void waitForFinalFileStatus(JTextArea area) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<DocumentListener> ref = new AtomicReference<>();

        onEdtAndWait(() -> {
            DocumentListener dl = new DocumentListener() {
                private void check() {
                    if (isFinalStatus(area.getText())) {
                        latch.countDown();
                    }
                }
                @Override public void insertUpdate(DocumentEvent e) { check(); }
                @Override public void removeUpdate(DocumentEvent e) { check(); }
                @Override public void changedUpdate(DocumentEvent e) { check(); }
            };
            ref.set(dl);
            area.getDocument().addDocumentListener(dl);

            // Handle the rare case the worker finished before we attached.
            if (isFinalStatus(area.getText())) {
                latch.countDown();
            }
        });

        boolean ok = latch.await(DEFAULT_WAIT_MS, TimeUnit.MILLISECONDS);

        onEdtAndWait(() -> {
            DocumentListener dl = ref.get();
            if (dl != null) {
                area.getDocument().removeDocumentListener(dl);
            }
        });

        if (!ok) {
            throw new AssertionError(
                    "Timed out waiting for file status update; last value: \"" + area.getText() + "\""
            );
        }
    }
}
