package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.table.TableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Insets;
import java.awt.LayoutManager;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Creates titled cards with a {@code Copy} action in the top-right so operators can extract the
 * contents of each StatsPanel card into the clipboard for sharing in issues, support threads, or
 * spreadsheets. The card keeps the familiar titled-border look; the copy button is embedded in
 * the header row next to the title so it does not consume layout space below.
 *
 * <p>Tables render as TSV (tab-separated values, one row per table row, preceded by a header
 * row); Misc Stats sections render as {@code section-label} blocks of {@code key: value} lines.
 * Chart copy is intentionally omitted; the Misc Stats card and per-index tables together cover
 * the data-capture use cases.</p>
 */
final class CardCopySupport {

    private static final String COPY_LABEL = "Copy";

    private CardCopySupport() {}

    /**
     * Builds a right-aligned copy toolbar for a multi-card panel (for example all Stats cards).
     *
     * @param tooltip copy-button tooltip
     * @param textSupplier clipboard payload supplier
     * @return header row for placement above stacked stats cards
     */
    static JPanel buildCopyOnlyToolbar(String tooltip, Supplier<String> textSupplier) {
        JPanel header = new JPanel(new BorderLayout(8, 0));
        header.setName("statsCopyToolbar");
        header.setOpaque(false);

        JButton copyButton = buildCopyButton("Stats", textSupplier);
        copyButton.setName("copy.All Stats");
        copyButton.setToolTipText(tooltip);

        JPanel eastBox = new JPanel();
        eastBox.setOpaque(false);
        eastBox.setLayout(new BoxLayout(eastBox, BoxLayout.X_AXIS));
        eastBox.add(Box.createHorizontalGlue());
        eastBox.add(copyButton);
        header.add(eastBox, BorderLayout.EAST);

        Dimension headerPref = header.getPreferredSize();
        header.setMaximumSize(new Dimension(Integer.MAX_VALUE, headerPref.height));
        return header;
    }

    /**
     * Inserts a compact "Copy" header row at the top of an existing card without disturbing the
     * card's own titled border or BoxLayout body layout.
     *
     * <ul>
     *   <li>Box-layout cards (Misc Stats): the header is inserted at index 0 so it appears just
     *       below the titled border at the top of the card.</li>
     *   <li>Border-layout cards (tables): the card's existing {@code NORTH} content (the table
     *       header row) is moved into a stacked container so the copy-button row sits above it
     *       without replacing it.</li>
     *   <li>Other layouts: the header is added without position; visual placement may vary.</li>
     * </ul>
     *
     * <p>{@code textSupplier} is invoked each time the button is pressed so the returned text
     * always reflects the current state.</p>
     */
    static void attachCopyButton(JPanel card, String title, Supplier<String> textSupplier) {
        JPanel header = buildHeader(title, textSupplier);
        LayoutManager layout = card.getLayout();
        if (layout instanceof BoxLayout) {
            card.add(header, 0);
            return;
        }
        if (layout instanceof BorderLayout bl) {
            Component existingNorth = bl.getLayoutComponent(BorderLayout.NORTH);
            if (existingNorth == null) {
                card.add(header, BorderLayout.NORTH);
                return;
            }
            card.remove(existingNorth);
            JPanel stacked = new JPanel();
            stacked.setLayout(new BoxLayout(stacked, BoxLayout.Y_AXIS));
            stacked.setOpaque(false);
            header.setAlignmentX(Component.LEFT_ALIGNMENT);
            if (existingNorth instanceof JComponent jc) {
                jc.setAlignmentX(Component.LEFT_ALIGNMENT);
            }
            stacked.add(header);
            stacked.add(existingNorth);
            card.add(stacked, BorderLayout.NORTH);
            return;
        }
        card.add(header);
    }

    private static JPanel buildHeader(String title, Supplier<String> textSupplier) {
        // The card's own TitledBorder renders the title; we intentionally do NOT repeat it here
        // so the Copy button sits alone on the right without a bold label duplicating the border.
        JPanel header = new JPanel(new BorderLayout(8, 0));
        header.setOpaque(false);

        JButton copyButton = buildCopyButton(title, textSupplier);
        JPanel eastBox = new JPanel();
        eastBox.setOpaque(false);
        eastBox.setLayout(new BoxLayout(eastBox, BoxLayout.X_AXIS));
        eastBox.add(Box.createHorizontalGlue());
        eastBox.add(copyButton);
        header.add(eastBox, BorderLayout.EAST);

        // Clamp the header's max height to its preferred height. Parent BoxLayout.Y_AXIS cards
        // (Misc Stats) compute their preferred size before this header is inserted, then fix the
        // card height. Without a max-height clamp, the header (Swing default max ~Short.MAX_VALUE)
        // would compete with the card's bottom verticalGlue for the resulting surplus and absorb
        // a chunk of vertical space, pushing the buttons away from the top and creating a gap
        // above the first section.
        Dimension headerPref = header.getPreferredSize();
        header.setMaximumSize(new Dimension(Integer.MAX_VALUE, headerPref.height));

        return header;
    }

    private static JButton buildCopyButton(String title, Supplier<String> textSupplier) {
        JButton copyButton = new JButton(COPY_LABEL);
        copyButton.setName("copy." + title);
        copyButton.setToolTipText("Copy the contents of this card to the clipboard");
        copyButton.setFocusable(false);
        copyButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        copyButton.setMargin(new Insets(1, 8, 1, 8));
        Font bodyFont = new JLabel().getFont().deriveFont(Font.PLAIN);
        copyButton.setFont(bodyFont);
        FontMetrics fm = copyButton.getFontMetrics(bodyFont);
        int textWidth = fm.stringWidth(COPY_LABEL);
        int buttonWidth = textWidth + 24;
        Dimension preferred = copyButton.getPreferredSize();
        int buttonHeight = Math.max(18, preferred.height - 4);
        Dimension fixed = new Dimension(buttonWidth, buttonHeight);
        copyButton.setPreferredSize(fixed);
        copyButton.setMinimumSize(fixed);
        copyButton.addActionListener(e -> copyToClipboard(title, textSupplier));
        return copyButton;
    }

    private static void copyToClipboard(String title, Supplier<String> textSupplier) {
        try {
            String payload = textSupplier.get();
            if (payload == null) {
                payload = "";
            }
            StringSelection selection = new StringSelection(payload);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
            if (RuntimeConfig.isExportRunning()) {
                Logger.logInfoPanelOnly("[StatsPanel] Copied " + title + " to clipboard ("
                        + payload.length() + " chars).");
            }
        } catch (RuntimeException ex) {
            if (RuntimeConfig.isExportRunning()) {
                Logger.logWarnPanelOnly("[StatsPanel] Copy failed for " + title + ": "
                        + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage()));
            }
        }
    }

    /** Renders a {@link JTable}'s contents as TSV: header row, then one body row per line. */
    static String tableToTsv(JTable table) {
        if (table == null) {
            return "";
        }
        TableModel model = table.getModel();
        String[] headers = new String[model.getColumnCount()];
        for (int c = 0; c < headers.length; c++) {
            headers[c] = model.getColumnName(c);
        }
        List<String[]> rows = new ArrayList<>(model.getRowCount());
        for (int r = 0; r < model.getRowCount(); r++) {
            String[] row = new String[headers.length];
            for (int c = 0; c < headers.length; c++) {
                Object value = model.getValueAt(r, c);
                row[c] = value == null ? "" : value.toString();
            }
            rows.add(row);
        }
        return rowsToTsv(headers, rows);
    }

    /**
     * Renders column headers and body rows as TSV without a Swing table.
     *
     * @param columnNames header labels in column order
     * @param rows body rows aligned with {@code columnNames}
     * @return tab-separated text with a trailing newline after each row
     */
    static String rowsToTsv(String[] columnNames, List<String[]> rows) {
        if (columnNames == null || columnNames.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(256);
        for (int c = 0; c < columnNames.length; c++) {
            if (c > 0) {
                sb.append('\t');
            }
            sb.append(safe(columnNames[c]));
        }
        sb.append('\n');
        if (rows != null) {
            for (String[] row : rows) {
                for (int c = 0; c < columnNames.length; c++) {
                    if (c > 0) {
                        sb.append('\t');
                    }
                    String cell = row != null && c < row.length && row[c] != null ? row[c] : "";
                    sb.append(safe(cell));
                }
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Renders a named set of key/value groups as a human-readable text block. Used by the Misc
     * Stats card and any future grouped metric cards. {@code sections} maps section title -> key
     * -> value; iteration order is preserved so callers control layout.
     */
    static String sectionsToText(String cardTitle, Map<String, Map<String, String>> sections) {
        StringBuilder sb = new StringBuilder(256);
        sb.append(cardTitle).append('\n');
        for (Map.Entry<String, Map<String, String>> sectionEntry : sections.entrySet()) {
            sb.append('\n').append(sectionEntry.getKey()).append('\n');
            for (Map.Entry<String, String> row : sectionEntry.getValue().entrySet()) {
                sb.append("  ").append(row.getKey()).append(": ").append(row.getValue()).append('\n');
            }
        }
        return sb.toString();
    }

    private static String safe(String raw) {
        if (raw == null) {
            return "";
        }
        // Strip tab / newline so TSV columns stay aligned even when a cell value itself contains
        // one of those characters (unlikely for our stats, but cheap insurance).
        return raw.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }
}
