package ai.attackframework.tools.burp.testutils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Creates test-only paths under {@code build/tmp} instead of the system temp directory.
 *
 * <p>This keeps test artifacts out of the user's OS temp folder while still giving each test an
 * isolated workspace. Methods are thread-safe under normal Gradle test execution because each path
 * includes a random suffix.</p>
 */
public final class TestPathSupport {

    private static final Path ROOT = Path.of("build", "tmp", "attackframework-burp-exporter-tests");

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
}
