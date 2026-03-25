package ai.attackframework.tools.burp.sinks;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.ExportStats;

/**
 * File-backed FIFO queue used when in-memory traffic queue is full.
 *
 * <p>Each document is written as one JSON file in a dedicated spill directory.
 * This queue is process-local and best-effort: files are cleaned as they are
 * drained; malformed spill files are skipped with an error log. Thread-safe.</p>
 */
final class TrafficSpillFileQueue {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SPILL_DIR_NAME = "attackframework-burp-exporter-traffic-spill";
    private static final String SCHEMA_VERSION = "1";
    private static final String SPILL_SOURCE = "traffic_overflow";
    private static final long DEFAULT_MAX_AGE_MS = TimeUnit.DAYS.toMillis(3);
    private static final TypeReference<Map<String, Object>> DOC_TYPE = new TypeReference<>() { };

    private final Path directory;
    private final String projectId;
    private final long maxFiles;
    private final long maxBytes;
    private final long maxAgeMs;
    private final ReentrantLock lock = new ReentrantLock();
    private final Deque<Path> files = new ArrayDeque<>();
    private long totalBytes = 0;
    private long nextSequence = 1;
    private long recoveredCount = 0;
    private long recoveredBytes = 0;

    /**
     * Creates a queue with default limits under the system temp directory.
     */
    TrafficSpillFileQueue() {
        this(
                Path.of(System.getProperty("java.io.tmpdir"), SPILL_DIR_NAME),
                100_000L,
                512L * 1024L * 1024L,
                resolveProjectId(),
                DEFAULT_MAX_AGE_MS);
    }

    /**
     * Creates a queue with explicit location and limits.
     *
     * <p>Visible for tests.</p>
     *
     * @param directory spill directory path
     * @param maxFiles maximum number of queued spill files
     * @param maxBytes maximum total queued spill bytes
     */
    TrafficSpillFileQueue(Path directory, long maxFiles, long maxBytes) {
        this(directory, maxFiles, maxBytes, "test-project", DEFAULT_MAX_AGE_MS);
    }

    /**
     * Creates a queue with explicit location, limits, and project identity.
     *
     * <p>Visible for tests.</p>
     */
    TrafficSpillFileQueue(Path directory, long maxFiles, long maxBytes, String projectId, long maxAgeMs) {
        this.directory = directory;
        this.projectId = sanitizeProjectId(projectId);
        this.maxFiles = Math.max(1, maxFiles);
        this.maxBytes = Math.max(1, maxBytes);
        this.maxAgeMs = Math.max(1, maxAgeMs);
        initializeFromDisk();
    }

    /**
     * Writes one document to the spill directory.
     *
     * @param document traffic document to persist
     * @return {@code true} when queued, {@code false} when limits prevent spill
     */
    boolean offer(Map<String, Object> document) {
        if (document == null) {
            return false;
        }
        byte[] payload;
        try {
            payload = JSON.writeValueAsBytes(buildSpillEnvelope(document));
        } catch (IOException e) {
            Logger.logError("Traffic spill serialize failed: " + e.getMessage());
            return false;
        }
        lock.lock();
        try {
            pruneExpiredLocked(System.currentTimeMillis());
            if (files.size() >= maxFiles || (totalBytes + payload.length) > maxBytes) {
                return false;
            }
            ensureDirectoryExists();
            String name = String.format("%s-%020d.json", projectId, nextSequence++);
            Path target = directory.resolve(name);
            Path temp = directory.resolve(name + ".tmp");
            Files.write(temp, payload, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            files.addLast(target);
            totalBytes += payload.length;
            return true;
        } catch (IOException e) {
            Logger.logError("Traffic spill write failed: " + e.getMessage());
            return false;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Reads and removes the oldest spilled document.
     *
     * @return oldest spilled document, or {@code null} when empty
     */
    Map<String, Object> poll() {
        lock.lock();
        try {
            while (!files.isEmpty()) {
                Path file = files.removeFirst();
                byte[] payload;
                try {
                    payload = Files.readAllBytes(file);
                    Files.deleteIfExists(file);
                } catch (IOException e) {
                    Logger.logError("Traffic spill read/delete failed: " + e.getMessage());
                    continue;
                }
                totalBytes = Math.max(0, totalBytes - payload.length);
                try {
                    return extractDocument(payload);
                } catch (IOException e) {
                    Logger.logError("Traffic spill parse failed: " + e.getMessage());
                }
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the current number of spilled documents. */
    int size() {
        lock.lock();
        try {
            return files.size();
        } finally {
            lock.unlock();
        }
    }

    /** Returns the current number of bytes occupied by spilled documents. */
    long bytes() {
        lock.lock();
        try {
            return totalBytes;
        } finally {
            lock.unlock();
        }
    }

    /** Returns age in ms of the oldest spilled document, or 0 when empty/unavailable. */
    long oldestAgeMs() {
        lock.lock();
        try {
            Path oldest = files.peekFirst();
            if (oldest == null) {
                return 0;
            }
            long lastModified = Files.getLastModifiedTime(oldest).toMillis();
            return Math.max(0, System.currentTimeMillis() - lastModified);
        } catch (IOException ignored) {
            return 0;
        } finally {
            lock.unlock();
        }
    }

    /** Returns spill file count recovered from disk during initialization. */
    long recoveredCount() {
        lock.lock();
        try {
            return recoveredCount;
        } finally {
            lock.unlock();
        }
    }

    /** Returns recovered spill byte count from disk during initialization. */
    long recoveredBytes() {
        lock.lock();
        try {
            return recoveredBytes;
        } finally {
            lock.unlock();
        }
    }

    /** Returns absolute spill directory path for diagnostics. */
    String directoryPath() {
        return directory.toAbsolutePath().toString();
    }

    /**
     * Clears all currently queued spill files owned by this queue instance.
     */
    void clear() {
        lock.lock();
        try {
            for (Path path : files) {
                deleteSpillFile(path);
            }
            files.clear();
            totalBytes = 0;
        } finally {
            lock.unlock();
        }
    }

    private void initializeFromDisk() {
        lock.lock();
        try {
            ensureDirectoryExists();
            files.clear();
            totalBytes = 0;
            nextSequence = 1;
            recoveredCount = 0;
            recoveredBytes = 0;
            cleanupTempFilesLocked();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.json")) {
                for (Path path : stream) {
                    if (isOwnedSpillFile(path)) {
                        files.add(path);
                    }
                }
            }
            Deque<Path> ordered = files.stream()
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .collect(ArrayDeque::new, Deque::addLast, Deque::addAll);
            files.clear();
            files.addAll(ordered);
            pruneExpiredLocked(System.currentTimeMillis());
            for (Path path : files) {
                try {
                    long fileBytes = Files.size(path);
                    totalBytes += fileBytes;
                    long seq = parseSequence(path);
                    if (seq >= nextSequence) {
                        nextSequence = seq + 1;
                    }
                } catch (IOException ignored) {
                    // Skip files that cannot be stat-ed; poll() will skip on read failure too.
                }
            }
            recoveredCount = files.size();
            recoveredBytes = totalBytes;
        } catch (IOException e) {
            Logger.logError("Traffic spill init failed: " + e.getMessage());
        } finally {
            lock.unlock();
        }
    }

    private void ensureDirectoryExists() throws IOException {
        Files.createDirectories(directory);
    }

    private static long parseSequence(Path path) {
        String file = path.getFileName().toString();
        int lastDash = file.lastIndexOf('-');
        if (lastDash > 0) {
            int dot = file.indexOf('.', lastDash + 1);
            if (dot > lastDash + 1) {
                try {
                    return Long.parseLong(file.substring(lastDash + 1, dot));
                } catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        int dot = file.indexOf('.');
        if (dot <= 0) {
            return -1;
        }
        try {
            return Long.parseLong(file.substring(0, dot));
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private static String resolveProjectId() {
        try {
            var api = MontoyaApiProvider.get();
            if (api != null && api.project() != null) {
                String raw = api.project().id();
                if (raw != null && !raw.isBlank()) {
                    return sanitizeProjectId(raw);
                }
            }
        } catch (Throwable ignored) {
            // Keep spill path resilient during Burp startup lifecycle transitions.
        }
        return "unknown-project";
    }

    private static String sanitizeProjectId(String raw) {
        if (raw == null || raw.isBlank()) {
            return "unknown-project";
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_') {
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append('-');
            }
        }
        String normalized = sb.toString().replaceAll("-{2,}", "-");
        normalized = normalized.replaceAll("^-+", "").replaceAll("-+$", "");
        return normalized.isBlank() ? "unknown-project" : normalized;
    }

    private Map<String, Object> buildSpillEnvelope(Map<String, Object> document) {
        Map<String, Object> envelope = new HashMap<>();
        Map<String, Object> meta = new HashMap<>();
        long now = System.currentTimeMillis();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("source", SPILL_SOURCE);
        meta.put("project_id", projectId);
        meta.put("enqueued_at_ms", now);
        try {
            meta.put("extension_version", Version.get());
        } catch (IllegalStateException ignored) {
            // Tests may not load from packaged JAR; keep spill metadata optional.
        }
        envelope.put("meta", meta);
        envelope.put("document", document);
        return envelope;
    }

    private Map<String, Object> extractDocument(byte[] payload) throws IOException {
        JsonNode root = JSON.readTree(payload);
        JsonNode docNode = root.get("document");
        if (docNode != null && docNode.isObject()) {
            return JSON.convertValue(docNode, DOC_TYPE);
        }
        return JSON.convertValue(root, DOC_TYPE);
    }

    private void pruneExpiredLocked(long nowMs) {
        long cutoffMs = nowMs - maxAgeMs;
        if (cutoffMs <= 0) {
            return;
        }
        long prunedCount = 0;
        Deque<Path> survivors = new ArrayDeque<>(files.size());
        for (Path path : files) {
            if (isExpired(path, cutoffMs)) {
                deleteSpillFile(path);
                prunedCount++;
            } else {
                survivors.addLast(path);
            }
        }
        files.clear();
        files.addAll(survivors);
        if (prunedCount > 0) {
            ExportStats.recordTrafficSpillExpiredPruned(prunedCount);
            ExportStats.recordTrafficDropReason("spill_retention_prune", prunedCount);
        }
    }

    private static boolean isExpired(Path path, long cutoffMs) {
        try {
            return Files.getLastModifiedTime(path).toMillis() < cutoffMs;
        } catch (IOException ignored) {
            return false;
        }
    }

    private void deleteSpillFile(Path path) {
        try {
            long fileBytes = Files.exists(path) ? Files.size(path) : 0;
            if (Files.deleteIfExists(path)) {
                totalBytes = Math.max(0, totalBytes - fileBytes);
            }
        } catch (IOException ignored) {
            // Keep best-effort retention cleanup non-fatal.
        }
    }

    private void cleanupTempFilesLocked() {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.tmp")) {
            for (Path tmp : stream) {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException ignored) {
            // Ignore stale temporary files from interrupted writes.
        }
    }

    private boolean isOwnedSpillFile(Path path) {
        String fileName = path.getFileName().toString();
        if (fileName.startsWith(projectId + "-")) {
            return true;
        }
        // Compatibility: load pre-project-id spill files named only by sequence.
        int dot = fileName.indexOf('.');
        if (dot <= 0) {
            return false;
        }
        for (int i = 0; i < dot; i++) {
            if (!Character.isDigit(fileName.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}

