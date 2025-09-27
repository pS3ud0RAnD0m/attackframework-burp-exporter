package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.IndexNaming;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.InputMap;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.event.KeyEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static ai.attackframework.tools.burp.testutils.Reflect.get;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Headless verification of field-scoped Enter bindings in ConfigPanel.
 *
 * Goals:
 *  - Press Enter on {@code filePathField} to trigger the same code path as clicking "Create Files".
 *  - Press Enter on {@code openSearchUrlField} to trigger the same code path as clicking "Test Connection".
 *
 * Design notes (deterministic & fast):
 *  - We simulate Enter via {@link JTextField#postActionEvent()} (no Toolkit events).
 *  - We await UI changes via a DocumentListener + CountDownLatch (EDT-safe).
 *  - For files, we pre-create all expected files to yield the deterministic “already existed” outcome.
 *  - For OpenSearch, we point to 127.0.0.1:1 to force a quick failure path; we assert transition
 *    from “Testing ...” to a non-empty final state.
 */
@Tag("headless")
class ConfigPanelEnterBindingsHeadlessTest {
    private static final long DEFAULT_WAIT_MS = 8000;
    private static final long TESTING_WAIT_MS = 3000;
    private static final String TESTING_TEXT  = "Testing ...";

    @Test
    void pressEnterOnFilePathField_triggersCreateFiles_andUpdatesStatus() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JTextField pathField = get(panel, "filePathField");
        JTextArea fileStatus = get(panel, "fileStatus");
        assertEnterBindingPresent(pathField);

        List<String> sources   = Arrays.asList("settings", "sitemap", "findings", "traffic");
        List<String> baseNames = IndexNaming.computeIndexBaseNames(sources);
        List<String> jsonNames = IndexNaming.toJsonFileNames(baseNames);

        Path tmpDir = Files.createTempDirectory("af-burp-enter-files-");
        for (String name : jsonNames) Files.createFile(tmpDir.resolve(name));

        onEdtAndWait(() -> pathField.setText(tmpDir.toString()));
        onEdtAndWait(pathField::postActionEvent);

        waitForFinalFileStatus(fileStatus);

        String status = fileStatus.getText().toLowerCase(Locale.ROOT);
        assertTrue(status.contains("already existed"),
                "Expected 'already existed' after Enter; actual:\n" + fileStatus.getText());
    }

    @Test
    void pressEnterOnOpenSearchUrlField_triggersTestConnection_andUpdatesStatus() throws Exception {
        ConfigPanel panel = new ConfigPanel();

        JCheckBox osEnable = get(panel, "openSearchSinkCheckbox");
        onEdtAndWait(() -> osEnable.setSelected(true));

        JTextField urlField = get(panel, "openSearchUrlField");
        JTextArea osStatus  = get(panel, "openSearchStatus");
        assertEnterBindingPresent(urlField);

        onEdtAndWait(() -> urlField.setText("http://127.0.0.1:1"));
        onEdtAndWait(urlField::postActionEvent);

        waitForTestingStatus(osStatus);
        waitForOpenSearchFinal(osStatus);

        String finalText = osStatus.getText();
        assertNotEquals(TESTING_TEXT, finalText, "OpenSearch status should advance past 'Testing ...'");
        assertTrue(finalText != null && finalText.trim().length() > 3,
                "Expected a non-trivial final status message.");
    }

    // ---------- helpers ----------

    /** Confirms Enter is mapped in the InputMap and resolvable in the ActionMap. */
    private static void assertEnterBindingPresent(JTextField field) {
        InputMap im = field.getInputMap(JComponent.WHEN_FOCUSED);
        Object actionKey = im.get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
        assertNotNull(actionKey, "Expected an InputMap binding for VK_ENTER");
        assertNotNull(field.getActionMap().get(actionKey),
                "Expected an ActionMap entry for the VK_ENTER binding key: " + actionKey);
    }

    /** Waits specifically for the transient “Testing ...” text used by the Test Connection flow. */
    private static void waitForTestingStatus(JTextArea area) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        DocumentListener[] holder = new DocumentListener[1];

        onEdtAndWait(() -> {
            DocumentListener dl = new DocumentListener() {
                private void check() { if (TESTING_TEXT.equals(area.getText())) latch.countDown(); }
                @Override public void insertUpdate(DocumentEvent e) { check(); }
                @Override public void removeUpdate(DocumentEvent e) { check(); }
                @Override public void changedUpdate(DocumentEvent e) { check(); }
            };
            holder[0] = dl;
            area.getDocument().addDocumentListener(dl);
            if (TESTING_TEXT.equals(area.getText())) latch.countDown();
        });

        boolean ok = latch.await(TESTING_WAIT_MS, TimeUnit.MILLISECONDS);

        onEdtAndWait(() -> {
            if (holder[0] != null) area.getDocument().removeDocumentListener(holder[0]);
        });

        if (!ok) fail("Timed out waiting for OpenSearch status to equal '" + TESTING_TEXT + "'. Last value: " + area.getText());
    }

    private static boolean isFinalFileStatus(String s) {
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

    private static void waitForFinalFileStatus(JTextArea area) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        DocumentListener[] holder = new DocumentListener[1];

        onEdtAndWait(() -> {
            DocumentListener dl = new DocumentListener() {
                private void check() { if (isFinalFileStatus(area.getText())) latch.countDown(); }
                @Override public void insertUpdate(DocumentEvent e) { check(); }
                @Override public void removeUpdate(DocumentEvent e) { check(); }
                @Override public void changedUpdate(DocumentEvent e) { check(); }
            };
            holder[0] = dl;
            area.getDocument().addDocumentListener(dl);
            if (isFinalFileStatus(area.getText())) latch.countDown();
        });

        boolean ok = latch.await(DEFAULT_WAIT_MS, TimeUnit.MILLISECONDS);

        onEdtAndWait(() -> {
            if (holder[0] != null) area.getDocument().removeDocumentListener(holder[0]);
        });

        if (!ok) fail("Timed out waiting for file status update; last value: \"" + area.getText() + "\"");
    }

    /** Waits for OpenSearch status to advance past the transient “Testing ...” message. */
    private static void waitForOpenSearchFinal(JTextArea area) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        DocumentListener[] holder = new DocumentListener[1];

        onEdtAndWait(() -> {
            DocumentListener dl = new DocumentListener() {
                private void check() {
                    String txt = area.getText();
                    if (txt != null && !TESTING_TEXT.equals(txt) && !txt.trim().isEmpty()) {
                        latch.countDown();
                    }
                }
                @Override public void insertUpdate(DocumentEvent e) { check(); }
                @Override public void removeUpdate(DocumentEvent e) { check(); }
                @Override public void changedUpdate(DocumentEvent e) { check(); }
            };
            holder[0] = dl;
            area.getDocument().addDocumentListener(dl);
            String txt = area.getText();
            if (txt != null && !TESTING_TEXT.equals(txt) && !txt.trim().isEmpty()) {
                latch.countDown();
            }
        });

        boolean ok = latch.await(DEFAULT_WAIT_MS, TimeUnit.MILLISECONDS);

        onEdtAndWait(() -> {
            if (holder[0] != null) area.getDocument().removeDocumentListener(holder[0]);
        });

        if (!ok) fail("Timed out waiting for OpenSearch status to advance beyond '" + TESTING_TEXT + "'. Last value: " + area.getText());
    }

    /** Runs the given block on the EDT, blocking until completion (avoids race conditions in tests). */
    private static void onEdtAndWait(Runnable r) throws Exception {
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            javax.swing.SwingUtilities.invokeAndWait(r);
        }
    }
}
