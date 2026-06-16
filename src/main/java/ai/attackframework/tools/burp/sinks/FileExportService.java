package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/**
 * Shared dispatcher for file-based exports.
 *
 * <p>This service fans out prepared documents to enabled on-disk formats. It is process-local and
 * safe for concurrent use.</p>
 */
public final class FileExportService {

    private static final Map<String, FileSink> JSONL_SINKS = new ConcurrentHashMap<>();
    private static final Map<String, FileSink> BULK_SINKS = new ConcurrentHashMap<>();
    private static final Map<String, RootState> ROOT_STATES = new ConcurrentHashMap<>();

    private FileExportService() { }

    /** Emits one prepared document to all enabled file formats. */
    public static void emit(PreparedExportDocument document) {
        if (document == null || !RuntimeConfig.isAnyFileExportEnabled()) {
            return;
        }
        long startedAtMs = System.currentTimeMillis();
        String root = RuntimeConfig.fileExportRoot();
        Path rootPath = Path.of(root);
        RootState rootState = rootState(rootPath);

        if (rootState.isGloballyDisabled()) {
            return;
        }

        FileSink jsonl = RuntimeConfig.isFileJsonlEnabled() ? jsonlSink(root, document.indexName()) : null;
        FileSink bulk = RuntimeConfig.isFileBulkNdjsonEnabled() ? bulkSink(root, document.indexName()) : null;
        long plannedBytes = 0L;
        if (jsonl != null) {
            plannedBytes += jsonl.estimateBytes(document);
        }
        if (bulk != null) {
            plannedBytes += bulk.estimateBytes(document);
        }
        if (!rootState.allowWrite(rootPath, plannedBytes)) {
            recordFailure(document, rootState.reason());
            return;
        }

        long written = 0L;
        if (jsonl != null) {
            written += jsonl.appendDocument(document);
        }
        if (bulk != null) {
            written += bulk.appendDocument(document);
        }
        if (written > 0L) {
            rootState.recordWrite(written);
            FileExportStats.recordSuccess(document.indexKey(), 1);
            FileExportStats.recordExportedBytes(document.indexKey(), written);
            FileExportStats.recordLastWriteDurationMs(document.indexKey(), System.currentTimeMillis() - startedAtMs);
            FileExportStats.recordLastError(document.indexKey(), null);
            recordTrafficSuccess(document);
        } else {
            recordFailure(document, "File export write produced no bytes.");
        }
    }

    /** Emits a batch of prepared documents to all enabled file formats. */
    public static void emitBatch(List<PreparedExportDocument> documents) {
        emitPreparedChunk(documents);
    }

    /**
     * Emits one snapshot bulk chunk with a single root disk check and batched bulk-ndjson append.
     */
    public static void emitPreparedChunk(List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty() || !RuntimeConfig.isAnyFileExportEnabled()) {
            return;
        }
        PreparedExportDocument first = documents.getFirst();
        String root = RuntimeConfig.fileExportRoot();
        Path rootPath = Path.of(root);
        RootState rootState = rootState(rootPath);
        if (rootState.isGloballyDisabled()) {
            return;
        }

        FileSink jsonl = RuntimeConfig.isFileJsonlEnabled() ? jsonlSink(root, first.indexName()) : null;
        FileSink bulk = RuntimeConfig.isFileBulkNdjsonEnabled() ? bulkSink(root, first.indexName()) : null;
        long plannedBytes = 0L;
        if (jsonl != null) {
            for (PreparedExportDocument document : documents) {
                plannedBytes += jsonl.estimateBytes(document);
            }
        }
        if (bulk != null) {
            for (PreparedExportDocument document : documents) {
                plannedBytes += bulk.estimateBytes(document);
            }
        }
        if (!rootState.allowWrite(rootPath, plannedBytes)) {
            String reason = rootState.reason();
            for (PreparedExportDocument document : documents) {
                recordFailure(document, reason);
            }
            return;
        }

        long startedAtMs = System.currentTimeMillis();
        long written = 0L;
        if (jsonl != null) {
            written += jsonl.appendBatch(documents);
        }
        if (bulk != null) {
            written += bulk.appendBatch(documents);
        }
        if (written > 0L) {
            rootState.recordWrite(written);
            FileExportStats.recordSuccess(first.indexKey(), documents.size());
            FileExportStats.recordExportedBytes(first.indexKey(), written);
            FileExportStats.recordLastWriteDurationMs(
                    first.indexKey(), System.currentTimeMillis() - startedAtMs);
            FileExportStats.recordLastError(first.indexKey(), null);
            for (PreparedExportDocument document : documents) {
                recordTrafficSuccess(document);
            }
        } else {
            for (PreparedExportDocument document : documents) {
                recordFailure(document, "File export write produced no bytes.");
            }
        }
    }

    /** Disables file export for the current root for the remainder of the run. */
    public static void disableCurrentRoot(String reason) {
        String root = RuntimeConfig.fileExportRoot();
        if (root == null || root.isBlank() || reason == null || reason.isBlank()) {
            return;
        }
        RuntimeConfig.disableFileDestination();
        rootState(Path.of(root)).disableAll(reason.trim(), false);
    }

    /** Clears cached sink instances and runtime disable state. */
    public static void resetForRuntime() {
        JSONL_SINKS.clear();
        BULK_SINKS.clear();
        ROOT_STATES.clear();
    }

    /** Clears cached sink instances, primarily for tests and lifecycle resets. */
    public static void resetForTests() {
        resetForRuntime();
        FileExportStats.resetForTests();
    }

    /** Creates export files for the selected sources and enabled file formats. */
    public static List<FileInitResult> createSelectedExportFiles(List<String> selectedSources) {
        return createSelectedExportFiles(selectedSources, () -> true);
    }

    /** Creates export files for the selected sources and enabled file formats. */
    public static List<FileInitResult> createSelectedExportFiles(
            List<String> selectedSources,
            BooleanSupplier shouldContinue
    ) {
        Path rootPath;
        try {
            rootPath = FileUtil.requireAbsoluteDirectoryPath(RuntimeConfig.fileExportRoot());
        } catch (IOException e) {
            return List.of(new FileInitResult(
                    "files",
                    "(invalid path)",
                    null,
                    FileUtil.Status.FAILED,
                    e.getMessage()));
        }

        List<FileInitResult> results = new java.util.ArrayList<>();
        for (String shortName : IndexNaming.computeSelectedIndexKeys(selectedSources)) {
            if (shouldContinue != null && !shouldContinue.getAsBoolean()) {
                break;
            }
            String baseName = RuntimeConfig.indexNameForKey(shortName);
            String displayName = IndexNaming.displayNameForIndexKey(shortName);
            if (RuntimeConfig.isFileJsonlEnabled()) {
                String fileName = baseName + ".jsonl";
                Logger.logInfoPanelOnly("[Files] Creating file for " + displayName + " (.jsonl).");
                FileUtil.CreateResult created = FileUtil.ensureFiles(rootPath, List.of(fileName)).getFirst();
                Logger.logInfoPanelOnly("[Files] File result for " + displayName + " (.jsonl): " + created.status() + ".");
                results.add(new FileInitResult(shortName, ".jsonl", created.path(), created.status(), created.error()));
            }
            if (RuntimeConfig.isFileBulkNdjsonEnabled()) {
                String fileName = baseName + ".ndjson";
                Logger.logInfoPanelOnly("[Files] Creating file for " + displayName + " (.ndjson).");
                FileUtil.CreateResult created = FileUtil.ensureFiles(rootPath, List.of(fileName)).getFirst();
                Logger.logInfoPanelOnly("[Files] File result for " + displayName + " (.ndjson): " + created.status() + ".");
                results.add(new FileInitResult(shortName, ".ndjson", created.path(), created.status(), created.error()));
            }
        }
        return results;
    }

    private static FileSink jsonlSink(String root, String indexName) {
        return JSONL_SINKS.computeIfAbsent(root + "|" + indexName, key -> new JsonlFileSink(Path.of(root), indexName));
    }

    private static FileSink bulkSink(String root, String indexName) {
        return BULK_SINKS.computeIfAbsent(root + "|" + indexName, key -> new BulkNdjsonFileSink(Path.of(root), indexName));
    }

    private static RootState rootState(Path rootPath) {
        String key = rootPath.toAbsolutePath().normalize().toString();
        return ROOT_STATES.computeIfAbsent(key, ignored -> RootState.initialize(rootPath));
    }

    private static void recordFailure(PreparedExportDocument document, String message) {
        FileExportStats.recordFailure(document.indexKey(), 1);
        FileExportStats.recordLastError(document.indexKey(), message);
        recordTrafficFailure(document);
    }

    public record FileInitResult(
            String shortName,
            String format,
            Path path,
            FileUtil.Status status,
            String error
    ) { }

    /**
     * Credits a successful file write for a traffic document against its route bucket.
     *
     * <p>No-op for non-traffic documents and for prepared entries without a resolvable body.
     * Traffic-only side effect: increments {@link FileExportStats} per-route success counters
     * via {@link TrafficRouteBucket#recordFileSuccess(TrafficRouteBucket.Route, long)}.</p>
     *
     * @param document prepared document whose route should receive the credit
     */
    private static void recordTrafficSuccess(PreparedExportDocument document) {
        if (!"traffic".equals(document.indexKey()) || document.document() == null) {
            return;
        }
        TrafficRouteBucket.recordFileSuccess(TrafficRouteBucket.fromDocument(document.document()), 1);
    }

    /**
     * Attributes a failed file write for a traffic document against its route bucket.
     *
     * <p>No-op for non-traffic documents and for prepared entries without a resolvable body.
     * Traffic-only side effect: increments {@link FileExportStats} per-route failure counters
     * via {@link TrafficRouteBucket#recordFileFailure(TrafficRouteBucket.Route, long)}.</p>
     *
     * @param document prepared document whose route should receive the failure
     */
    private static void recordTrafficFailure(PreparedExportDocument document) {
        if (!"traffic".equals(document.indexKey()) || document.document() == null) {
            return;
        }
        TrafficRouteBucket.recordFileFailure(TrafficRouteBucket.fromDocument(document.document()), 1);
    }

    private static final class RootState {
        private final Path rootPath;
        private long totalBytes;
        private volatile boolean globallyDisabled;
        private volatile String globalDisableReason;

        private RootState(Path rootPath) {
            this.rootPath = rootPath;
        }

        static RootState initialize(Path rootPath) {
            RootState state = new RootState(rootPath);
            state.scanExistingFiles();
            return state;
        }

        boolean isGloballyDisabled() {
            return globallyDisabled;
        }

        String reason() {
            return globalDisableReason;
        }

        synchronized boolean allowWrite(Path rootPath, long plannedBytes) {
            if (plannedBytes <= 0L || globallyDisabled) {
                return false;
            }
            if (RuntimeConfig.isFileDiskUsagePercentEnabled()) {
                Integer usedPercent = diskUsedPercent(rootPath);
                int threshold = RuntimeConfig.fileDiskUsagePercent();
                if (usedPercent != null && usedPercent >= threshold) {
                    disableAll("File export stopped: destination volume is at " + usedPercent
                            + "% used (threshold " + threshold + "%).", true);
                    return false;
                }
            }
            if (RuntimeConfig.isFileTotalCapEnabled() && totalBytes + plannedBytes > RuntimeConfig.fileTotalCapBytes()) {
                disableAll("File export stopped: total cap " + humanBytes(RuntimeConfig.fileTotalCapBytes())
                        + " reached under " + rootPath + ".", true);
                return false;
            }
            return true;
        }

        synchronized void recordWrite(long writtenBytes) {
            if (writtenBytes <= 0L) {
                return;
            }
            totalBytes += writtenBytes;
        }

        synchronized void disableAll(String reason, boolean continueOpensearch) {
            if (globallyDisabled) {
                return;
            }
            globallyDisabled = true;
            String suffix = continueOpensearch && !RuntimeConfig.openSearchUrl().isBlank()
                    ? " OpenSearch export continues."
                    : "";
            String message = reason + suffix;
            globalDisableReason = message;
            Logger.logError(message);
            ControlStatusBridge.post(message);
        }

        private void scanExistingFiles() {
            if (!Files.isDirectory(rootPath)) {
                return;
            }
            try {
                java.util.Set<Path> candidates = new java.util.LinkedHashSet<>();
                for (String baseName : RuntimeConfig.allIndexNames().values()) {
                    candidates.add(rootPath.resolve(baseName + ".jsonl"));
                    candidates.add(rootPath.resolve(baseName + ".ndjson"));
                }
                for (Path path : candidates) {
                    if (Files.isRegularFile(path)) {
                        totalBytes += Files.size(path);
                    }
                }
            } catch (IOException e) {
                Logger.logError("[Files] Size scan failed for " + rootPath + ": " + e.getMessage());
            }
        }

        private static Integer diskUsedPercent(Path rootPath) {
            try {
                Path target = Files.exists(rootPath) ? rootPath : rootPath.toAbsolutePath().getParent();
                if (target == null) {
                    target = rootPath.toAbsolutePath();
                }
                FileStore store = Files.getFileStore(target);
                long total = store.getTotalSpace();
                long usable = store.getUsableSpace();
                if (total <= 0L) {
                    return null;
                }
                long used = Math.max(0L, total - usable);
                return (int) Math.min(100L, Math.round((used * 100.0d) / total));
            } catch (IOException | RuntimeException e) {
                Logger.logError("[Files] Disk-usage check failed for " + rootPath + ": " + e.getMessage());
                return null;
            }
        }

        private static String humanBytes(long bytes) {
            long safe = Math.max(0L, bytes);
            double value = safe;
            String unit = "B";
            if (safe >= 1024L * 1024L * 1024L) {
                value = safe / (1024.0d * 1024.0d * 1024.0d);
                unit = "GiB";
            } else if (safe >= 1024L * 1024L) {
                value = safe / (1024.0d * 1024.0d);
                unit = "MiB";
            } else if (safe >= 1024L) {
                value = safe / 1024.0d;
                unit = "KiB";
            }
            return String.format(java.util.Locale.ROOT, unit.equals("B") ? "%.0f %s" : "%.2f %s", value, unit);
        }
    }
}
