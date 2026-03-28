package ai.attackframework.tools.burp.testutils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Creates test-only paths under {@code build/tmp} instead of the system temp directory.
 *
 * <p>This keeps test artifacts out of the user's OS temp folder while still giving each test an
 * isolated workspace. Methods are thread-safe under normal Gradle test execution because each path
 * includes a random suffix.</p>
 */
public final class TestPathSupport {

    private static final Path ROOT = Path.of("build", "tmp", "attackframework-burp-exporter-tests");
    private static final Path DEFAULT_UI_FILE_ROOT = Path.of("/path/to/directory");
    private static final AtomicBoolean DEFAULT_UI_ROOT_CLEANED = new AtomicBoolean(false);

    private TestPathSupport() { }

    /**
     * Creates a unique test directory under {@code build/tmp}.
     *
     * @param prefix logical test prefix used in the directory name
     * @return created directory path
     * @throws IOException when the directory cannot be created
     */
    public static Path createDirectory(String prefix) throws IOException {
        Files.createDirectories(ROOT);
        return Files.createDirectories(ROOT.resolve(prefix + "-" + UUID.randomUUID()));
    }

    /**
     * Creates a unique test file path under {@code build/tmp}.
     *
     * @param prefix logical test prefix used in the file name
     * @param suffix file suffix, including the leading dot when desired
     * @return created file path
     * @throws IOException when the file cannot be created
     */
    public static Path createFile(String prefix, String suffix) throws IOException {
        Files.createDirectories(ROOT);
        return Files.createFile(ROOT.resolve(prefix + "-" + UUID.randomUUID() + suffix));
    }

    /** Returns the default file root shown in the ConfigPanel UI. */
    public static Path defaultUiFileRoot() {
        ensureDefaultUiFileRootPrepared();
        return DEFAULT_UI_FILE_ROOT;
    }

    /**
     * Returns whether the provided directory can be created and written.
     *
     * <p>When the reserved default UI root is checked, suite-start cleanup runs first so tests do
     * not inherit stale files from prior runs.</p>
     */
    public static boolean isWritableDirectory(Path root) {
        if (DEFAULT_UI_FILE_ROOT.equals(root)) {
            ensureDefaultUiFileRootPrepared();
        }
        try {
            Files.createDirectories(root);
            Path probe = Files.createTempFile(root, "attackframework-test-write-", ".tmp");
            Files.deleteIfExists(probe);
            return true;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** Deletes attackframework export artifacts from the provided directory when they exist. */
    public static void cleanupExportArtifacts(Path root) throws IOException {
        if (root == null || !Files.isDirectory(root)) {
            return;
        }
        List<Path> toDelete = new ArrayList<>();
        try (var stream = Files.newDirectoryStream(root, "attackframework-tool-burp*")) {
            for (Path path : stream) {
                if (Files.isRegularFile(path)) {
                    toDelete.add(path);
                }
            }
        }
        for (Path path : toDelete) {
            Files.deleteIfExists(path);
        }
    }

    /**
     * Prepares the reserved default UI export root once per JVM.
     *
     * <p>This is the file-side equivalent of centralized test OpenSearch cleanup: before the suite
     * uses {@code /path/to/directory}, remove leftover content from earlier runs. Cleanup is
     * intentionally scoped to this exact synthetic test path and is best-effort.</p>
     */
    public static void ensureDefaultUiFileRootPrepared() {
        if (DEFAULT_UI_ROOT_CLEANED.compareAndSet(false, true)) {
            cleanReservedDefaultUiRootContents();
        }
    }

    /** Resets the one-time default-root cleanup guard for focused tests of this helper. */
    static void resetDefaultUiFileRootPreparationForTests() {
        DEFAULT_UI_ROOT_CLEANED.set(false);
    }

    private static void cleanReservedDefaultUiRootContents() {
        try {
            Files.createDirectories(DEFAULT_UI_FILE_ROOT);
            List<Path> toDelete = new ArrayList<>();
            try (var stream = Files.list(DEFAULT_UI_FILE_ROOT)) {
                stream.forEach(toDelete::add);
            }
            for (Path path : toDelete) {
                deleteRecursively(path);
            }
        } catch (IOException | RuntimeException ignored) {
            // Best-effort cleanup for the reserved synthetic default UI root.
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            return;
        }
        if (Files.isDirectory(path)) {
            try (var stream = Files.list(path)) {
                for (Path child : stream.toList()) {
                    deleteRecursively(child);
                }
            }
        }
        Files.deleteIfExists(path);
    }
}
