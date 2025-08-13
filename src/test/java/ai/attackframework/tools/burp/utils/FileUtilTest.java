package ai.attackframework.tools.burp.utils;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class FileUtilTest {

    @Test
    void ensureJsonFiles_createsMissingFiles_thenReportsExistsOnSecondRun() throws IOException {
        Path tmp = java.nio.file.Files.createTempDirectory("af-json-root-");
        Path f1 = tmp.resolve("alpha.json");
        Path f2 = tmp.resolve("nested/beta.json");

        // First run should create files
        var first = FileUtil.ensureJsonFiles(tmp, List.of("alpha.json", "nested/beta.json"));
        assertThat(first).hasSize(2);
        assertThat(java.nio.file.Files.exists(f1)).isTrue();
        assertThat(java.nio.file.Files.exists(f2)).isTrue();
        assertThat(first.stream().map(FileUtil.CreateResult::status))
                .containsExactlyInAnyOrder(FileUtil.Status.CREATED, FileUtil.Status.CREATED);

        // Second run should find files already exist
        var second = FileUtil.ensureJsonFiles(tmp, List.of("alpha.json", "nested/beta.json"));
        assertThat(second.stream().map(FileUtil.CreateResult::status))
                .containsExactlyInAnyOrder(FileUtil.Status.EXISTS, FileUtil.Status.EXISTS);
    }

    @Test
    void ensureJsonFiles_returnsFailedWhenRootIsNotADirectory() throws IOException {
        // Simulate a root path that's actually a file
        Path fileAsRoot = java.nio.file.Files.createTempFile("af-not-a-dir-", ".tmp");

        var res = FileUtil.ensureJsonFiles(fileAsRoot, List.of("x.json"));
        assertThat(res).hasSize(1);
        assertThat(res.getFirst().status()).isEqualTo(FileUtil.Status.FAILED);
        assertThat(res.getFirst().error()).isNotBlank();
    }
}
