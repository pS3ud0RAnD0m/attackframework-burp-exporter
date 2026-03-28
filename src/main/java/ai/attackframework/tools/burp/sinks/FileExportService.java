package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.FileExportStats;
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
    private static final String EXPORT_FILE_GLOB = "attackframework-tool-burp*";

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
        if (documents == null || documents.isEmpty()) {
            return;
        }
        for (PreparedExportDocument document : documents) {
            emit(document);
        }
    }

    /** Disables file export for the current root for the remainder of the run. */
    public static void disableCurrentRoot(String reason) {
        String root = RuntimeConfig.fileExportRoot();
        if (root == null || root.isBlank() || reason == null || reason.isBlank()) {
            return;
        }
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

    private static void recordTrafficSuccess(PreparedExportDocument document) {
        if (!"traffic".equals(document.indexKey())) {
            return;
        }
        String toolType = toolTypeOf(document);
        if ("PROXY_WEBSOCKET".equals(toolType)) {
            FileExportStats.recordTrafficSourceSuccess("proxy_websocket", 1);
            return;
        }
        if ("PROXY_HISTORY".equals(toolType)) {
            FileExportStats.recordTrafficSourceSuccess("proxy_history_snapshot", 1);
        } else if (toolType != null && !toolType.isBlank()) {
            FileExportStats.recordTrafficToolTypeCaptured(toolType, 1);
        } else {
            FileExportStats.recordTrafficToolTypeCaptured("UNKNOWN", 1);
        }
    }

    private static void recordTrafficFailure(PreparedExportDocument document) {
        if (!"traffic".equals(document.indexKey())) {
            return;
        }
        String toolType = toolTypeOf(document);
        if ("PROXY_WEBSOCKET".equals(toolType)) {
            FileExportStats.recordTrafficSourceFailure("proxy_websocket", 1);
            return;
        }
        if ("PROXY_HISTORY".equals(toolType)) {
            FileExportStats.recordTrafficSourceFailure("proxy_history_snapshot", 1);
        }
    }

    private static String toolTypeOf(PreparedExportDocument document) {
        if (document == null || document.document() == null) {
            return null;
        }
        Object value = document.document().get("tool_type");
        return value == null ? null : String.valueOf(value);
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
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(rootPath, EXPORT_FILE_GLOB)) {
                for (Path path : stream) {
                    if (!Files.isRegularFile(path)) {
                        continue;
                    }
                    long size = Files.size(path);
                    totalBytes += size;
                }
            } catch (IOException e) {
                Logger.logError("File export size scan failed for " + rootPath + ": " + e.getMessage());
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
                Logger.logError("File export disk-usage check failed for " + rootPath + ": " + e.getMessage());
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
