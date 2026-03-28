package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import ai.attackframework.tools.burp.utils.DiskSpaceGuard;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

/**
 * Base class for per-index line-oriented file sinks that append to one file per format.
 *
 * <p>Each append opens the target path with {@link StandardOpenOption#CREATE} and
 * {@link StandardOpenOption#APPEND}, writes the payload, and returns immediately. These sinks do
 * not keep a long-lived writer open, so they do not require separate flush/close lifecycle hooks
 * between export runs.</p>
 */
abstract class RotatingLineFileSink implements FileSink {

    private final Path rootDirectory;
    private final String indexName;
    private final String extension;
    private Path currentPath;

    RotatingLineFileSink(Path rootDirectory, String indexName, String extension) {
        this.rootDirectory = rootDirectory;
        this.indexName = indexName;
        this.extension = extension;
    }

    @Override
    public synchronized long estimateBytes(PreparedExportDocument document) {
        List<String> lines = linesFor(document);
        if (lines == null || lines.isEmpty()) {
            return 0L;
        }
        return String.join("", lines).getBytes(StandardCharsets.UTF_8).length;
    }

    @Override
    public synchronized long appendDocument(PreparedExportDocument document) {
        if (document == null) {
            return 0L;
        }
        return appendLines(linesFor(document));
    }

    protected abstract List<String> linesFor(PreparedExportDocument document);

    private long appendLines(List<String> lines) {
        if (lines == null || lines.isEmpty()) {
            return 0L;
        }
        try {
            initializeIfNeeded();
            String payload = String.join("", lines);
            byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
            Path target = currentPath;
            DiskSpaceGuard.ensureWritable(target, bytes.length, "file export");
            Files.writeString(target, payload, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return bytes.length;
        } catch (IOException e) {
            Logger.logError("File export write failed for " + indexName + extension + ": " + e.getMessage());
            return 0L;
        }
    }

    private void initializeIfNeeded() throws IOException {
        Files.createDirectories(rootDirectory);
        if (currentPath != null) {
            return;
        }
        currentPath = defaultPath();
    }

    private Path defaultPath() {
        return rootDirectory.resolve(indexName + extension);
    }
}
