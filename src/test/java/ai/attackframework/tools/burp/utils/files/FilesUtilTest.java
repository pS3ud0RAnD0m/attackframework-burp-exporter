package ai.attackframework.tools.burp.utils.files;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class FilesUtilTest {

    @Test
    void ensureJsonFiles_createsMissingFiles_thenReportsExistsOnSecondRun() throws IOException {
        Path tmp = Files.createTempDirectory("af-json-root-");
        Path f1 = tmp.resolve("alpha.json");
        Path f2 = tmp.resolve("nested/beta.json");

        // First run should create files
        var first = FilesUtil.ensureJsonFiles(tmp, List.of("alpha.json", "nested/beta.json"));
        assertThat(first).hasSize(2);
        assertThat(Files.exists(f1)).isTrue();
        assertThat(Files.exists(f2)).isTrue();
        assertThat(first.stream().map(FilesUtil.CreateResult::status))
                .containsExactlyInAnyOrder(FilesUtil.Status.CREATED, FilesUtil.Status.CREATED);

        // Second run should find files already exist
        var second = FilesUtil.ensureJsonFiles(tmp, List.of("alpha.json", "nested/beta.json"));
        assertThat(second.stream().map(FilesUtil.CreateResult::status))
                .containsExactlyInAnyOrder(FilesUtil.Status.EXISTS, FilesUtil.Status.EXISTS);
    }

    @Test
    void ensureJsonFiles_returnsFailedWhenRootIsNotADirectory() throws IOException {
        // Simulate a root path that's actually a file
        Path fileAsRoot = Files.createTempFile("af-not-a-dir-", ".tmp");

        var res = FilesUtil.ensureJsonFiles(fileAsRoot, List.of("x.json"));
        assertThat(res).hasSize(1);
        assertThat(res.getFirst().status()).isEqualTo(FilesUtil.Status.FAILED);
        assertThat(res.getFirst().error()).isNotBlank();
    }
}
