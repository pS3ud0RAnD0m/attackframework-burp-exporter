package ai.attackframework.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.Timer;

import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;
import ai.attackframework.tools.burp.utils.TrafficExportStats;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Panel that displays live resource and traffic-export metrics.
 *
 * <p>Updates every few seconds via a Swing Timer. Shows JVM heap (used/max/free),
 * traffic docs indexed, push failures, export running state, and last error.
 * Caller must construct on the EDT.</p>
 */
public class StatsPanel extends JPanel {

    private static final int REFRESH_INTERVAL_MS = 3000;
    private static final long MEGABYTE = 1024 * 1024;

    private final JTextArea statsArea;

    /**
     * Creates the Stats panel and starts the refresh timer.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        statsArea = new JTextArea();
        statsArea.setEditable(false);
        statsArea.setLineWrap(true);
        statsArea.setWrapStyleWord(true);
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        add(ScrollPanes.wrap(statsArea), BorderLayout.CENTER);

        Timer timer = new Timer(REFRESH_INTERVAL_MS, e -> statsArea.setText(buildStatsText()));
        timer.setRepeats(true);
        timer.start();

        statsArea.setText(buildStatsText());
    }

    private static String buildStatsText() {
        Runtime rt = Runtime.getRuntime();
        long maxMb = rt.maxMemory() / MEGABYTE;
        long totalMb = rt.totalMemory() / MEGABYTE;
        long freeMb = rt.freeMemory() / MEGABYTE;
        long usedMb = totalMb - freeMb;

        String osUrl = RuntimeConfig.openSearchUrl();
        boolean urlSet = osUrl != null && !osUrl.isBlank();
        boolean exportRunning = RuntimeConfig.isExportRunning();

        long success = TrafficExportStats.getSuccessCount();
        long failure = TrafficExportStats.getFailureCount();
        String lastError = TrafficExportStats.getLastError();

        StringBuilder sb = new StringBuilder();
        sb.append("JVM Heap (MB)\n");
        sb.append("  used: ").append(usedMb).append("  max: ").append(maxMb).append("  free: ").append(freeMb).append("\n\n");
        sb.append("Traffic export\n");
        sb.append("  docs indexed: ").append(success).append("\n");
        sb.append("  push failures: ").append(failure).append("\n");
        sb.append("  export running: ").append(exportRunning ? "yes" : "no").append("\n");
        sb.append("  OpenSearch URL set: ").append(urlSet ? "yes" : "no").append("\n");
        if (lastError != null) {
            sb.append("\nLast error\n  ").append(lastError).append("\n");
        }
        return sb.toString();
    }
}
