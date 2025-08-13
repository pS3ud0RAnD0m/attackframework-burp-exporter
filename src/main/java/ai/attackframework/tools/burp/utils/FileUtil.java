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

    public enum Status { CREATED, EXISTS, FAILED }
    public record CreateResult(Path path, Status status, String error) {}

    private FileUtil() {}

    /**
     * Convenience overload to keep panel code free of Path construction.
     * Delegates to the Path-based variant.
     */
    public static List<CreateResult> ensureJsonFiles(String rootDir, List<String> fileNames) {
        return ensureJsonFiles(Path.of(rootDir), fileNames);
    }

    /**
     * Ensure a set of JSON files exist under {@code rootDir}. Creates parent dirs as needed.
     * For each file, returns CREATED, EXISTS, or FAILED with error message.
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
            try {
                if (java.nio.file.Files.exists(p)) {
                    out.add(new CreateResult(p, Status.EXISTS, null));
                    continue;
                }

                Path parent = p.getParent();
                if (parent != null) {
                    java.nio.file.Files.createDirectories(parent);
                }

                try {
                    java.nio.file.Files.createFile(p);
                } catch (FileAlreadyExistsException ignored) {
                    out.add(new CreateResult(p, Status.EXISTS, null));
                    continue;
                }

                java.nio.file.Files.writeString(p, "{}\n", StandardCharsets.UTF_8);
                out.add(new CreateResult(p, Status.CREATED, null));

            } catch (DirectoryNotEmptyException e) {
                out.add(new CreateResult(p, Status.FAILED, "Directory not empty: " + e.getMessage()));
            } catch (IOException e) {
                out.add(new CreateResult(p, Status.FAILED, e.getMessage()));
            } catch (RuntimeException e) {
                out.add(new CreateResult(p, Status.FAILED, e.toString()));
            }
        }

        return out;
    }

    // ---------- Generic helpers used by ConfigPanel import/export ----------

    /** Ensure a {@code .json} extension on the provided file name (case-insensitive). */
    public static File ensureJsonExtension(File f) {
        if (f == null) return null;
        String nameLower = f.getName().toLowerCase();
        if (nameLower.endsWith(".json")) return f;
        File parent = f.getParentFile();
        return (parent == null) ? new File(f.getName() + ".json") : new File(parent, f.getName() + ".json");
    }

    /** Write UTF-8 text to a file, creating parent directories if necessary. */
    public static void writeStringCreateDirs(Path file, String content) throws IOException {
        Path parent = file.getParent();
        if (parent != null) java.nio.file.Files.createDirectories(parent);
        java.nio.file.Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    /** Read UTF-8 text from a file. */
    public static String readString(Path file) throws IOException {
        return java.nio.file.Files.readString(file, StandardCharsets.UTF_8);
    }

    /** Create a temp file and write UTF-8 content to it. Returns the temp file path. */
    public static Path writeTempFile(String prefix, String suffix, String content) throws IOException {
        Path p = java.nio.file.Files.createTempFile(prefix, suffix);
        java.nio.file.Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }
}
