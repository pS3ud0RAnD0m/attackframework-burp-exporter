package ai.attackframework.tools.burp.utils;

import java.lang.management.BufferPoolMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.util.List;

/**
 * JVM/process resource metrics sampled from the JMX {@code ManagementFactory} beans.
 *
 * <p>Centralized so the periodic exporter stats snapshot, the Stats panel Misc Stats card, and
 * the plain-text stats summary all read identical values. JMX calls are cheap but may throw in
 * restricted environments; each field is collected independently and falls back to {@code -1}
 * (or {@code NaN} for CPU load) rather than propagating the failure.</p>
 */
public final class SystemMetrics {

    private SystemMetrics() {}

    /**
     * Immutable process-wide resource snapshot.
     *
     * <p>Negative numeric fields signal "unavailable" - either JMX failed to report or the
     * platform does not expose the metric. {@link #processCpuLoad} returns {@link Double#NaN}
     * when the {@code com.sun.management} extension is not reachable (for example on non-HotSpot
     * JVMs or restricted security managers).</p>
     *
     * <p>{@code heapCommittedBytes} is the heap currently allocated from the OS
     * ({@link Runtime#totalMemory()}). It bounds {@code heapUsedBytes} from above and
     * tracks more closely with process RSS than {@code heapUsedBytes} alone -- HotSpot does not
     * eagerly return committed heap to the OS after a peak, so committed often stays high after
     * used drops, which is what makes Task Manager / RSS still look elevated post-Stop.</p>
     */
    public record Snapshot(
            long heapUsedBytes,
            long heapCommittedBytes,
            long heapMaxBytes,
            long nonHeapUsedBytes,
            long nonHeapMaxBytes,
            int threadCount,
            int peakThreadCount,
            long gcCollectionCount,
            long gcCollectionTimeMs,
            long uptimeMs,
            int availableProcessors,
            double processCpuLoad,
            long directBufferUsedBytes,
            long mappedBufferUsedBytes) {}

    /** Returns {@code true} when any JMX field above reported a usable value. */
    public static Snapshot snapshot() {
        Runtime rt = Runtime.getRuntime();
        long heapCommitted = rt.totalMemory();
        long heapUsed = Math.max(-1L, heapCommitted - rt.freeMemory());
        long heapMax = rt.maxMemory();

        long nonHeapUsed = -1L;
        long nonHeapMax = -1L;
        int threadCount = -1;
        int peakThreadCount = -1;
        long gcCount = -1L;
        long gcTimeMs = -1L;
        long uptimeMs = -1L;
        int availableProcessors = rt.availableProcessors();
        double processCpuLoad = Double.NaN;

        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            MemoryUsage nonHeap = memoryBean.getNonHeapMemoryUsage();
            if (nonHeap != null) {
                nonHeapUsed = nonHeap.getUsed() >= 0 ? nonHeap.getUsed() : -1L;
                nonHeapMax = nonHeap.getMax() >= 0 ? nonHeap.getMax() : -1L;
            }
        } catch (RuntimeException ignored) {
            // JMX may be restricted in some environments.
        }

        try {
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            threadCount = Math.max(-1, threadBean.getThreadCount());
            peakThreadCount = Math.max(-1, threadBean.getPeakThreadCount());
        } catch (RuntimeException ignored) {
            // Thread bean may be disabled; keep defaults.
        }

        try {
            RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
            uptimeMs = Math.max(-1L, runtimeBean.getUptime());
        } catch (RuntimeException ignored) {
            // Runtime bean failure; keep default.
        }

        try {
            List<GarbageCollectorMXBean> gcBeans = ManagementFactory.getGarbageCollectorMXBeans();
            long counts = 0L;
            long times = 0L;
            boolean any = false;
            for (GarbageCollectorMXBean gc : gcBeans) {
                long c = gc.getCollectionCount();
                long t = gc.getCollectionTime();
                if (c >= 0) {
                    counts += c;
                    any = true;
                }
                if (t >= 0) {
                    times += t;
                    any = true;
                }
            }
            if (any) {
                gcCount = counts;
                gcTimeMs = times;
            }
        } catch (RuntimeException ignored) {
            // GC beans may be unavailable; keep defaults.
        }

        try {
            OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
            if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOs) {
                double load = sunOs.getProcessCpuLoad();
                if (load >= 0.0) {
                    processCpuLoad = load;
                }
            }
        } catch (RuntimeException | LinkageError ignored) {
            // Non-HotSpot JVM or restricted; leave as NaN.
        }

        // Off-heap buffer pool totals (NIO direct + memory-mapped). These do not count against
        // heap_used or non_heap_used; they are separate process-level allocations tracked by the
        // JVM. Reporting them closes the observability gap where HTTP client TLS buffers and
        // other direct allocations inflate RSS without showing up in heap metrics.
        long directBufferUsed = -1L;
        long mappedBufferUsed = -1L;
        try {
            for (BufferPoolMXBean pool : ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)) {
                String name = pool.getName();
                long used = pool.getMemoryUsed();
                if (used < 0) {
                    continue;
                }
                if ("direct".equals(name)) {
                    directBufferUsed = used;
                } else if ("mapped".equals(name)) {
                    mappedBufferUsed = used;
                }
            }
        } catch (RuntimeException ignored) {
            // BufferPoolMXBean may be unavailable on some JVMs; keep defaults.
        }

        return new Snapshot(
                heapUsed,
                heapCommitted,
                heapMax,
                nonHeapUsed,
                nonHeapMax,
                threadCount,
                peakThreadCount,
                gcCount,
                gcTimeMs,
                uptimeMs,
                availableProcessors,
                processCpuLoad,
                directBufferUsed,
                mappedBufferUsed);
    }
}
