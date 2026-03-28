package ai.attackframework.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class TestPathSupportTest {

    @Test
    void defaultUiFileRoot_preparesReservedRootByDeletingExistingContents() throws Exception {
        Path root = TestPathSupport.defaultUiFileRoot();
        Assumptions.assumeTrue(TestPathSupport.isWritableDirectory(root),
                "Reserved default UI root is not writable in this environment");
        Files.createDirectories(root);
        Files.writeString(root.resolve("leftover.txt"), "leftover");
        Path nestedDir = Files.createDirectories(root.resolve("nested-dir"));
        Files.writeString(nestedDir.resolve("nested.txt"), "nested");

        TestPathSupport.resetDefaultUiFileRootPreparationForTests();
        Path prepared = TestPathSupport.defaultUiFileRoot();

        assertThat(prepared).isEqualTo(root);
        assertThat(Files.list(prepared).toList()).isEmpty();
    }
}
