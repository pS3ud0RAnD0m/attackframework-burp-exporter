package ai.attackframework.tools.burp.utils.files;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class FilesUtil {

    public enum Status { CREATED, EXISTS, FAILED }

    public record CreateResult(Path path, Status status, String error) {}

    private FilesUtil() {}

    public static List<CreateResult> ensureJsonFiles(Path rootDir, List<String> fileNames) {
        List<CreateResult> out = new ArrayList<>(fileNames.size());

        try {
            Files.createDirectories(rootDir);
        } catch (IOException e) {
            for (String n : fileNames) {
                out.add(new CreateResult(rootDir.resolve(n), Status.FAILED, e.getMessage()));
            }
            return out;
        }

        for (String name : fileNames) {
            Path p = rootDir.resolve(name);
            try {
                if (Files.exists(p)) {
                    out.add(new CreateResult(p, Status.EXISTS, null));
                    continue;
                }

                Path parent = p.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }

                try {
                    Files.createFile(p);
                } catch (FileAlreadyExistsException ignored) {
                    out.add(new CreateResult(p, Status.EXISTS, null));
                    continue;
                }

                Files.writeString(p, "{}\n", StandardCharsets.UTF_8);
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
}
