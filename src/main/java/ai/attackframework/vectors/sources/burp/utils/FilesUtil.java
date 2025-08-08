package ai.attackframework.vectors.sources.burp.utils;

import java.io.IOException;
import java.nio.file.*;

public final class FilesUtil {

    private FilesUtil() {}

    public enum CreateStatus { CREATED, EXISTS, FAILED }

    public static final class CreateResult {
        private final CreateStatus status;
        private final Path path;
        private final String error;

        public CreateResult(CreateStatus status, Path path, String error) {
            this.status = status;
            this.path = path;
            this.error = error;
        }

        public CreateStatus status() { return status; }
        public Path path() { return path; }
        public String error() { return error; }
    }

    /**
     * Ensure a file exists under the given root. If root doesn't exist it will be created.
     */
    public static CreateResult ensureFile(String rootDir, String relativeFileName) {
        try {
            Path root = Paths.get(rootDir).toAbsolutePath().normalize();
            if (!Files.exists(root)) {
                Files.createDirectories(root);
            } else if (!Files.isDirectory(root)) {
                return new CreateResult(CreateStatus.FAILED, root, "Root path is not a directory");
            }

            Path target = root.resolve(relativeFileName).normalize();

            if (Files.exists(target)) {
                if (Files.isRegularFile(target)) {
                    return new CreateResult(CreateStatus.EXISTS, target, null);
                } else {
                    return new CreateResult(CreateStatus.FAILED, target, "Path exists but is not a regular file");
                }
            }

            // create empty file
            Files.createFile(target);
            return new CreateResult(CreateStatus.CREATED, target, null);

        } catch (IOException | SecurityException ex) {
            return new CreateResult(CreateStatus.FAILED, null, ex.getMessage());
        }
    }
}
