package ai.attackframework.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import javax.swing.JTextArea;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.ui.log.LogRenderer;
import ai.attackframework.tools.burp.ui.log.LogStore;

/**
 * Edge-case coverage for {@link LogRenderer}'s incremental-trim primitives.
 *
 * <p>The append/replaceLast happy paths are covered by {@link LogRendererAppendReplaceTest}.
 * This class focuses on {@code removeLeadingLines}, {@code prependLines}, and the
 * {@code lastContentLineBounds} clamp that powers {@code replaceLast} when a
 * {@code PlainDocument}'s synthetic trailing element is in play.</p>
 */
class LogRendererTrimEdgesTest {

    @Test
    void removeLeadingLines_onEmptyDocument_isNoOp() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);

        r.removeLeadingLines(0);
        r.removeLeadingLines(5);

        assertThat(text(pane)).isEmpty();
    }

    @Test
    void removeLeadingLines_withZeroOrNegative_isNoOp() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);
        r.append("b\n", LogStore.Level.INFO);

        r.removeLeadingLines(0);
        r.removeLeadingLines(-3);

        assertThat(text(pane)).isEqualTo("a\nb\n");
    }

    @Test
    void removeLeadingLines_clampsToContentLineCount() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);
        r.append("b\n", LogStore.Level.INFO);
        r.append("c\n", LogStore.Level.INFO);

        // Asking for more lines than exist still drains the document cleanly.
        r.removeLeadingLines(99);

        assertThat(text(pane)).isEmpty();
    }

    @Test
    void removeLeadingLines_preservesRemainingLinesIntact() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);
        r.append("b\n", LogStore.Level.INFO);
        r.append("c\n", LogStore.Level.INFO);
        r.append("d\n", LogStore.Level.INFO);

        r.removeLeadingLines(2);

        assertThat(text(pane)).isEqualTo("c\nd\n");
    }

    @Test
    void removeLeadingLines_thenAppend_keepsDocumentConsistent() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);
        r.append("b\n", LogStore.Level.INFO);

        r.removeLeadingLines(1);
        r.append("c\n", LogStore.Level.INFO);

        assertThat(text(pane)).isEqualTo("b\nc\n");
    }

    @Test
    void prependLines_intoEmptyDocument_writesText() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);

        r.prependLines("a\nb\n");

        assertThat(text(pane)).isEqualTo("a\nb\n");
    }

    @Test
    void prependLines_withNullOrEmpty_isNoOp() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("x\n", LogStore.Level.INFO);

        r.prependLines(null);
        r.prependLines("");

        assertThat(text(pane)).isEqualTo("x\n");
    }

    @Test
    void prependLines_keepsTrailingContent() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("c\n", LogStore.Level.INFO);
        r.append("d\n", LogStore.Level.INFO);

        r.prependLines("a\nb\n");

        assertThat(text(pane)).isEqualTo("a\nb\nc\nd\n");
    }

    @Test
    void replaceLast_onSingleLine_replacesThatLine_withoutClampError() throws Exception {
        // PlainDocument exposes a final synthetic line element whose endOffset == getLength()+1.
        // replaceLast must clamp so AbstractDocument.remove(start, len) does not throw.
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);

        r.replaceLast("z\n", LogStore.Level.INFO);

        assertThat(text(pane)).isEqualTo("z\n");
    }

    @Test
    void replaceLast_onMultiLine_onlyTouchesFinalLine() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);
        r.append("b\n", LogStore.Level.INFO);
        r.append("c\n", LogStore.Level.INFO);

        r.replaceLast("Z\n", LogStore.Level.INFO);

        assertThat(text(pane)).isEqualTo("a\nb\nZ\n");
    }

    @Test
    void replaceLast_onEmptyDocument_appendsAsFallback() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);

        r.replaceLast("only\n", LogStore.Level.INFO);

        assertThat(text(pane)).isEqualTo("only\n");
    }

    @Test
    void clear_removesAllContent() throws Exception {
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        r.append("a\n", LogStore.Level.INFO);
        r.append("b\n", LogStore.Level.INFO);

        r.clear();

        assertThat(text(pane)).isEmpty();
    }

    @Test
    void interleavedTrimAndAppend_yieldsExpectedDocument() throws Exception {
        // Mirrors the LogPanel suffix-diff path: trim the head, append a new tail.
        JTextArea pane = new JTextArea();
        LogRenderer r = new LogRenderer(pane);
        for (char c = 'a'; c <= 'e'; c++) {
            r.append(c + "\n", LogStore.Level.INFO);
        }

        r.removeLeadingLines(2);
        r.append("f\n", LogStore.Level.INFO);

        assertThat(text(pane)).isEqualTo("c\nd\ne\nf\n");
    }

    private static String text(JTextComponent component) throws Exception {
        Document doc = component.getDocument();
        return doc.getText(0, doc.getLength());
    }
}
