package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.IndexNaming;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Headless verification of the File sink flow in ConfigPanel.
 *
 * Intent:
 * - Clicking “Create Files” creates (or reports on) the expected JSON files.
 * - Final status is deterministic by pre-creating the files so the result must include “already existed”.
 *
 * Approach:
 * - Derive expected file names with IndexNaming to mirror production logic.
 * - Reach private Swing fields via the shared test Reflect helper to keep production visibility minimal.
 * - Wait for the worker completion using a DocumentListener + CountDownLatch (no sleeps).
 * - Run UI mutations on the EDT via onEdtAndWait.
 */
@Tag("headless")
class ConfigPanelFileSinkHeadlessTest {

    private static final long DEFAULT_WAIT_MS = 8000;

    @Test
    void createFilesButton_createsExpectedJsonFiles_andUpdatesStatus() throws Exception {
        // Arrange
        ConfigPanel panel = new ConfigPanel();

        // Build the list of expected JSON filenames and pre-create them so the final
        // status must include “already existed”.
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

        // Access private UI fields via the shared test Reflect helper.
        JTextField pathField = get(panel, "filePathField");
        JButton createBtn    = get(panel, "createFilesButton");
        JTextArea statusArea = get(panel, "fileStatus");

        // Act: set the path and click on the EDT.
        onEdtAndWait(() -> pathField.setText(tmpDir.toString()));
        onEdtAndWait(createBtn::doClick);

        // Assert: wait for the asynchronous worker to post the final status and verify the outcome.
        waitForFinalFileStatus(statusArea);

        String status = statusArea.getText().toLowerCase(Locale.ROOT);
        assertTrue(status.contains("already existed"),
                "Expecting final status to mention 'already existed'; actual:\n" + statusArea.getText());
    }

    /**
     * Runs the given task on the EDT and blocks until completion to avoid UI races.
     */
    private static void onEdtAndWait(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    /**
     * Returns true when the status text represents a final state after the worker completes.
     * Uses user-visible phrasing to avoid brittle coupling to implementation details.
     */
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
     * Waits until the file-status text reaches a final state or times out.
     * Attaches a listener so the test reacts immediately when the worker completes.
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

            // Handle the case where the worker finished before the listener was attached.
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
