package ai.attackframework.tools.burp.utils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Small file utilities used by the UI and sinks. Keeps I/O concerns out of UI code.
 */
public final class FileUtil {

    /**
     * Status of file creation attempts.
     */
    public enum Status { CREATED, EXISTS, FAILED }

    /**
     * Outcome of ensuring a JSON file exists.
     * <p>
     * @param path   target path
     * @param status creation status
     * @param error  error message when {@link Status#FAILED}
     */
    public record CreateResult(Path path, Status status, String error) {}

    private static final String JSON_EXTENSION = ".json";

    /**
     * Utility class; not instantiable.
     */
    private FileUtil() {}

    /**
     * Convenience overload to keep panel code free of Path construction.
     * Delegates to the Path-based variant.
     * <p>
     * @param rootDir   root directory string
     * @param fileNames file names to ensure
     * @return results per file
     */
    public static List<CreateResult> ensureJsonFiles(String rootDir, List<String> fileNames) {
        return ensureJsonFiles(Path.of(rootDir), fileNames);
    }

    /**
     * Ensure a set of JSON files exist under {@code rootDir}. Creates parent dirs as needed.
     * For each file, returns CREATED, EXISTS, or FAILED with error message.
     * <p>
     * @param rootDir   base directory
     * @param fileNames file names to create
     * @return creation results
     */
    public static List<CreateResult> ensureJsonFiles(Path rootDir, List<String> fileNames) {
        List<CreateResult> out = new ArrayList<>(fileNames.size());

        try {
            java.nio.file.Files.createDirectories(rootDir);
        } catch (IOException e) {
            for (String n : fileNames) {
                out.add(new CreateResult(rootDir.resolve(n), Status.FAILED, e.getMessage()));
            }
            return out;
        }

        for (String name : fileNames) {
            Path p = rootDir.resolve(name);
            out.add(ensureSingleJsonFile(p));
        }

        return out;
    }

    /**
     * Ensures a single JSON file exists, creating parent directories as needed.
     * <p>
     * @param p target path
     * @return result describing outcome
     */
    private static CreateResult ensureSingleJsonFile(Path p) {
        try {
            if (java.nio.file.Files.exists(p)) {
                return new CreateResult(p, Status.EXISTS, null);
            }

            Path parent = p.getParent();
            if (parent != null) {
                java.nio.file.Files.createDirectories(parent);
            }

            java.nio.file.Files.createFile(p);
            java.nio.file.Files.writeString(p, "{}\n", StandardCharsets.UTF_8);
            return new CreateResult(p, Status.CREATED, null);

        } catch (FileAlreadyExistsException e) {
            // File was created between the existence check and createFile call; treat as EXISTS.
            return new CreateResult(p, Status.EXISTS, null);
        } catch (DirectoryNotEmptyException e) {
            return new CreateResult(p, Status.FAILED, "Directory not empty: " + e.getMessage());
        } catch (IOException e) {
            return new CreateResult(p, Status.FAILED, e.getMessage());
        } catch (RuntimeException e) {
            return new CreateResult(p, Status.FAILED, e.toString());
        }
    }

    // ---------- Generic helpers used by ConfigPanel import/export ----------

    /**
     * Ensure a {@code .json} extension on the provided file name (case-insensitive).
     * <p>
     * @param f file to normalize
     * @return file with .json suffix ensured
     */
    public static File ensureJsonExtension(File f) {
        if (f == null) return null;
        String nameLower = f.getName().toLowerCase();
        if (nameLower.endsWith(JSON_EXTENSION)) return f;
        File parent = f.getParentFile();
        return (parent == null)
                ? new File(f.getName() + JSON_EXTENSION)
                : new File(parent, f.getName() + JSON_EXTENSION);
    }

    /**
     * Write UTF-8 text to a file, creating parent directories if necessary.
     * <p>
     * @param file    destination path
     * @param content content to write
     * @throws IOException when writing fails
     */
    public static void writeStringCreateDirs(Path file, String content) throws IOException {
        Path parent = file.getParent();
        if (parent != null) java.nio.file.Files.createDirectories(parent);
        java.nio.file.Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    /**
     * Read UTF-8 text from a file.
     * <p>
     * @param file file to read
     * @return file contents as string
     * @throws IOException when reading fails
     */
    public static String readString(Path file) throws IOException {
        return java.nio.file.Files.readString(file, StandardCharsets.UTF_8);
    }

    /**
     * Create a temp file and write UTF-8 content to it.
     * <p>
     * @param prefix  temp file prefix
     * @param suffix  temp file suffix
     * @param content content to write
     * @return path to created temp file
     * @throws IOException when creation or write fails
     */
    public static Path writeTempFile(String prefix, String suffix, String content) throws IOException {
        Path p = java.nio.file.Files.createTempFile(prefix, suffix);
        java.nio.file.Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }
}
