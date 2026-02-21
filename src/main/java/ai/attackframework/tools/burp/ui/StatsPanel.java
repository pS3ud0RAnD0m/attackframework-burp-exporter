package ai.attackframework.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;

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

        long nonHeapUsedMb = -1;
        long nonHeapMaxMb = -1;
        int threadCount = -1;
        long uptimeSec = -1;
        long gcCount = -1;
        long gcTimeSec = -1;
        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            MemoryUsage nonHeap = memoryBean.getNonHeapMemoryUsage();
            if (nonHeap != null && nonHeap.getUsed() >= 0) {
                nonHeapUsedMb = nonHeap.getUsed() / MEGABYTE;
                nonHeapMaxMb = nonHeap.getMax() >= 0 ? nonHeap.getMax() / MEGABYTE : -1;
            }
            threadCount = ManagementFactory.getThreadMXBean().getThreadCount();
            uptimeSec = ManagementFactory.getRuntimeMXBean().getUptime() / 1000;
            gcCount = ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionCount() >= 0 ? gc.getCollectionCount() : 0)
                    .sum();
            gcTimeSec = ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionTime() >= 0 ? gc.getCollectionTime() : 0)
                    .sum() / 1000;
        } catch (Exception ignored) {
            // JMX may be restricted
        }

        String osUrl = RuntimeConfig.openSearchUrl();
        boolean urlSet = osUrl != null && !osUrl.isBlank();
        boolean exportRunning = RuntimeConfig.isExportRunning();

        long success = TrafficExportStats.getSuccessCount();
        long failure = TrafficExportStats.getFailureCount();
        long lastPushMs = TrafficExportStats.getLastPushDurationMs();
        String lastError = TrafficExportStats.getLastError();

        StringBuilder sb = new StringBuilder();
        sb.append("JVM Heap (MB)\n");
        sb.append("  used: ").append(usedMb).append("  max: ").append(maxMb).append("  free: ").append(freeMb).append("\n");
        if (nonHeapUsedMb >= 0) {
            sb.append("JVM Non-heap (MB)  [metaspace, code cache]\n");
            sb.append("  used: ").append(nonHeapUsedMb).append("  max: ");
            if (nonHeapMaxMb >= 0) sb.append(nonHeapMaxMb); else sb.append("n/a");
            sb.append("\n");
        }
        if (threadCount >= 0) {
            sb.append("Thread count: ").append(threadCount).append("\n");
        }
        if (uptimeSec >= 0) {
            sb.append("JVM uptime (s): ").append(uptimeSec).append("\n");
        }
        if (gcCount >= 0) {
            sb.append("GC collections: ").append(gcCount).append("  total time (s): ").append(gcTimeSec).append("\n");
        }
        sb.append("\nTraffic export\n");
        sb.append("  docs indexed: ").append(success).append("\n");
        sb.append("  push failures: ").append(failure).append("\n");
        if (lastPushMs >= 0) {
            sb.append("  last push (ms): ").append(lastPushMs).append("\n");
        }
        sb.append("  export running: ").append(exportRunning ? "yes" : "no").append("\n");
        sb.append("  OpenSearch URL set: ").append(urlSet ? "yes" : "no").append("\n");
        if (lastError != null) {
            sb.append("\nLast error\n  ").append(lastError).append("\n");
        }
        return sb.toString();
    }
}
