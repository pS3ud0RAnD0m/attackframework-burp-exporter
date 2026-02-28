package ai.attackframework.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.ThreadMXBean;

import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.Timer;

import ai.attackframework.tools.burp.ui.primitives.ScrollPanes;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;

/**
 * Panel that displays live export and JVM metrics for all indexes.
 *
 * <p>Updates every few seconds via a Swing Timer. Shows export state, session
 * totals (all indexes), per-index table (docs pushed, queued, failures, last push ms,
 * last error), and process-wide JVM metrics (Burp + extensions). Caller must construct on the EDT.</p>
 */
public class StatsPanel extends JPanel {

    private static final int REFRESH_INTERVAL_MS = 3000;
    private static final long MEGABYTE = 1024 * 1024;
    private static final int ERROR_COL_MAX = 50;

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

    static String buildStatsText() {
        StringBuilder sb = new StringBuilder();

        // Export state
        String osUrl = RuntimeConfig.openSearchUrl();
        boolean urlSet = osUrl != null && !osUrl.isBlank();
        boolean exportRunning = RuntimeConfig.isExportRunning();
        sb.append("Export state\n");
        sb.append("  export running: ").append(exportRunning ? "yes" : "no").append("\n");
        sb.append("  OpenSearch URL set: ").append(urlSet ? "yes" : "no").append("\n\n");

        // Session totals
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();
        sb.append("Session totals (this session)\n");
        sb.append("  total docs pushed: ").append(totalSuccess).append("\n");
        sb.append("  total failures: ").append(totalFailure).append("\n\n");

        // By index (table)
        sb.append("By index\n");
        sb.append(String.format("  %-10s %12s %8s %10s %14s  %s%n",
                "Index", "Docs pushed", "Queued", "Failures", "Last push (ms)", "Last error"));
        sb.append("  ").append("-".repeat(10)).append(" ").append("-".repeat(12)).append(" ").append("-".repeat(8)).append(" ").append("-".repeat(10)).append(" ").append("-".repeat(14)).append("  ").append("-".repeat(ERROR_COL_MAX)).append("\n");
        for (String indexKey : ExportStats.getIndexKeys()) {
            long success = ExportStats.getSuccessCount(indexKey);
            int queued = ExportStats.getQueueSize(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            long lastPushMs = ExportStats.getLastPushDurationMs(indexKey);
            String lastError = ExportStats.getLastError(indexKey);
            String lastPushStr = lastPushMs >= 0 ? String.valueOf(lastPushMs) : "-";
            String errStr = lastError != null ? truncateForColumn(lastError, ERROR_COL_MAX) : "-";
            sb.append(String.format("  %-10s %12d %8d %10d %14s  %s%n",
                    indexKey, success, queued, failure, lastPushStr, errStr));
        }
        sb.append("\n");

        // JVM stats: process total, then our extension (threads by name), then Burp + other (derived)
        Runtime rt = Runtime.getRuntime();
        long maxMb = rt.maxMemory() / MEGABYTE;
        long totalMb = rt.totalMemory() / MEGABYTE;
        long freeMb = rt.freeMemory() / MEGABYTE;
        long usedMb = totalMb - freeMb;

        long nonHeapUsedMb = -1;
        long nonHeapMaxMb = -1;
        int processThreadCount = -1;
        int ourExtensionThreadCount = -1;
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
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            processThreadCount = threadBean.getThreadCount();
            ourExtensionThreadCount = countOurExtensionThreads(threadBean);
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

        // Process total (Burp + all extensions; single JVM)
        sb.append("Process total (Burp + all extensions)\n");
        sb.append("  heap (MB): used=").append(usedMb).append(" max=").append(maxMb).append(" free=").append(freeMb).append("\n");
        if (nonHeapUsedMb >= 0) {
            sb.append("  non-heap (MB): used=").append(nonHeapUsedMb).append(" max=");
            if (nonHeapMaxMb >= 0) sb.append(nonHeapMaxMb); else sb.append("n/a");
            sb.append("  [metaspace, code cache]\n");
        }
        if (processThreadCount >= 0) {
            sb.append("  thread count: ").append(processThreadCount).append("\n");
        }
        if (uptimeSec >= 0) {
            sb.append("  uptime (s): ").append(uptimeSec).append("\n");
        }
        if (gcCount >= 0) {
            sb.append("  GC collections: ").append(gcCount).append("  total time (s): ").append(gcTimeSec).append("\n");
        }
        sb.append("\n");

        // Our extension (threads by name; memory n/a)
        sb.append("Our extension (attackframework-burp-exporter)\n");
        if (ourExtensionThreadCount >= 0) {
            sb.append("  threads (by name): ").append(ourExtensionThreadCount).append("\n");
        }
        sb.append("  memory: n/a (JVM does not expose per-extension heap)\n");
        sb.append("  activity: see Session totals and By index above.\n");
        sb.append("\n");

        // Burp + other extensions (derived thread count; memory n/a)
        sb.append("Burp + other extensions\n");
        if (processThreadCount >= 0 && ourExtensionThreadCount >= 0) {
            int otherThreads = Math.max(0, processThreadCount - ourExtensionThreadCount);
            sb.append("  threads (approx): ").append(otherThreads).append("  (process total minus our threads)\n");
        }
        sb.append("  memory: n/a (shared process heap; not separable via JVM APIs).\n");

        return sb.toString();
    }

    /** Counts threads we create (by known name prefixes). Heuristic only. */
    private static int countOurExtensionThreads(ThreadMXBean threadBean) {
        long[] ids = threadBean.getAllThreadIds();
        int count = 0;
        for (long id : ids) {
            var info = threadBean.getThreadInfo(id);
            if (info != null) {
                String name = info.getThreadName();
                if (name != null && (name.contains("attackframework") || name.contains("OpenSearchRetryDrain"))) {
                    count++;
                }
            }
        }
        return count;
    }

    private static String truncateForColumn(String s, int maxLen) {
        if (s == null) return "-";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}
