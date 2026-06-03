package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ToolType;

/**
 * Regression test for {@link TrafficHttpHandlerSupport} orphan flushing.
 *
 * <p>Verifies that requests whose pending timestamp has aged past the orphan timeout are drained
 * into {@link TrafficExportQueue} and then removed from the pending-orphan map. The test
 * registers pending orphans via package-private test hooks so it stays independent of Burp's
 * {@code ObjectFactoryLocator}, which is not wired in unit tests.</p>
 */
class TrafficHttpHandlerOrphanFlushTest {

    @Test
    void flushOrphanedRequests_drainsAgedEntryToExportQueue() throws Exception {
        Path root = TestPathSupport.createDirectory("traffic-handler-orphan-flush");
        RuntimeConfig.updateState(fileOnlyTrafficState(root));
        RuntimeConfig.setExportRunning(true);
        try {
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();

            int messageId = 4242;
            seedAgedPendingOrphan(messageId, ToolType.REPEATER);

            int sizeBefore = TrafficExportQueue.getCurrentSize();
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            int sizeAfter = TrafficExportQueue.getCurrentSize();

            assertThat(sizeAfter - sizeBefore >= 1 || waitForFileExport(root)).isTrue();
            assertPendingOrphanRemoved(messageId);
        } finally {
            RuntimeConfig.setExportRunning(false);
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();
        }
    }

    @Test
    void flushOrphanedRequests_dropsAgedEntryWhenToolTypeDeselected() throws Exception {
        Path root = TestPathSupport.createDirectory("traffic-handler-orphan-deselected");
        RuntimeConfig.updateState(fileOnlyTrafficState(root, List.of("proxy")));
        RuntimeConfig.setExportRunning(true);
        try {
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();

            int messageId = 4343;
            seedAgedPendingOrphan(messageId, ToolType.REPEATER);

            int sizeBefore = TrafficExportQueue.getCurrentSize();
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            int sizeAfter = TrafficExportQueue.getCurrentSize();

            assertThat(sizeAfter).isEqualTo(sizeBefore);
            assertPendingOrphanRemoved(messageId);
        } finally {
            RuntimeConfig.setExportRunning(false);
            TrafficExportQueue.clearPendingWork();
            TrafficHttpHandlerSupport.clearPendingOrphansForTest();
        }
    }

    private static void seedAgedPendingOrphan(int messageId, ToolType toolType) {
        Map<String, Object> skeleton = new LinkedHashMap<>();
        skeleton.put("url", "https://example.test/orphan");
        skeleton.put("host", "example.test");
        skeleton.put("port", 443);
        skeleton.put("burp", Map.of("reporting_tool", toolType.toolName(), "message_id", messageId));

        TrafficHttpHandlerSupport.registerPendingOrphanForTest(
                messageId,
                skeleton,
                toolType,
                TrafficHttpHandlerSupport.RequestStageResolution.none());
    }

    private static boolean waitForFileExport(Path root) throws Exception {
        long deadline = System.currentTimeMillis() + 2_000;
        while (System.currentTimeMillis() < deadline) {
            try (var files = Files.walk(root)) {
                if (files.filter(Files::isRegularFile).anyMatch(TrafficHttpHandlerOrphanFlushTest::hasContent)) {
                    return true;
                }
            }
            Thread.sleep(50);
        }
        return false;
    }

    private static boolean hasContent(Path path) {
        try {
            return Files.size(path) > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static void assertPendingOrphanRemoved(int messageId) {
        assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(messageId))
                .as("flushOrphanedRequests must remove drained entries")
                .isFalse();
    }

    private static ConfigState.State fileOnlyTrafficState(Path root) {
        return fileOnlyTrafficState(root, List.of("repeater"));
    }

    private static ConfigState.State fileOnlyTrafficState(Path root, List<String> trafficToolTypes) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
                        false,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false,
                        "",
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                trafficToolTypes,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
