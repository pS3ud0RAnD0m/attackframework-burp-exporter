package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
 * populates the pending map directly via reflection so it stays independent of Burp's
 * {@code ObjectFactoryLocator} which is not wired in unit tests.</p>
 */
class TrafficHttpHandlerOrphanFlushTest {

    private static final String SUPPORT_CLASS = "ai.attackframework.tools.burp.sinks.TrafficHttpHandlerSupport";

    @Test
    void flushOrphanedRequests_drainsAgedEntryToExportQueue() throws Exception {
        Path root = TestPathSupport.createDirectory("traffic-handler-orphan-flush");
        RuntimeConfig.updateState(fileOnlyTrafficState(root));
        RuntimeConfig.setExportRunning(true);
        try {
            TrafficExportQueue.clearPendingWork();
            clearPendingOrphans();

            int messageId = 4242;
            seedAgedPendingOrphan(messageId, ToolType.REPEATER);

            int sizeBefore = TrafficExportQueue.getCurrentSize();
            invokeFlushOrphanedRequests();
            int sizeAfter = TrafficExportQueue.getCurrentSize();

            assertThat(sizeAfter - sizeBefore).isGreaterThanOrEqualTo(1);
            assertPendingOrphanRemoved(messageId);
        } finally {
            RuntimeConfig.setExportRunning(false);
            TrafficExportQueue.clearPendingWork();
            clearPendingOrphans();
        }
    }

    @SuppressWarnings("unchecked")
    private static void seedAgedPendingOrphan(int messageId, ToolType toolType) throws Exception {
        Class<?> supportCls = Class.forName(SUPPORT_CLASS);
        Class<?> pendingOrphanCls = Class.forName(SUPPORT_CLASS + "$PendingOrphan");
        Class<?> resolutionCls = Class.forName(SUPPORT_CLASS + "$RequestStageResolution");

        Method resolutionNone = resolutionCls.getDeclaredMethod("none");
        resolutionNone.setAccessible(true);
        Object resolution = resolutionNone.invoke(null);

        Map<String, Object> skeleton = new LinkedHashMap<>();
        skeleton.put("url", "https://example.test/orphan");
        skeleton.put("host", "example.test");
        skeleton.put("port", 443);
        skeleton.put("tool_type", toolType.name());
        skeleton.put("message_id", messageId);

        Constructor<?> ctor = pendingOrphanCls.getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        Object aged = ctor.newInstance(skeleton, 0L, toolType, resolution);

        Field pendingField = supportCls.getDeclaredField("pendingOrphans");
        pendingField.setAccessible(true);
        ConcurrentHashMap<Integer, Object> pending =
                (ConcurrentHashMap<Integer, Object>) pendingField.get(null);
        pending.put(messageId, aged);
    }

    private static void invokeFlushOrphanedRequests() throws Exception {
        Method m = Class.forName(SUPPORT_CLASS).getDeclaredMethod("flushOrphanedRequests");
        m.setAccessible(true);
        m.invoke(null);
    }

    @SuppressWarnings("unchecked")
    private static void assertPendingOrphanRemoved(int messageId) throws Exception {
        Field pendingField = Class.forName(SUPPORT_CLASS).getDeclaredField("pendingOrphans");
        pendingField.setAccessible(true);
        ConcurrentHashMap<Integer, Object> pending =
                (ConcurrentHashMap<Integer, Object>) pendingField.get(null);
        assertThat(pending.get(messageId))
                .as("flushOrphanedRequests must remove drained entries")
                .isNull();
    }

    @SuppressWarnings("unchecked")
    private static void clearPendingOrphans() throws Exception {
        Field pendingField = Class.forName(SUPPORT_CLASS).getDeclaredField("pendingOrphans");
        pendingField.setAccessible(true);
        ConcurrentHashMap<Integer, Object> pending =
                (ConcurrentHashMap<Integer, Object>) pendingField.get(null);
        pending.clear();
    }

    private static ConfigState.State fileOnlyTrafficState(Path root) {
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
                List.of("repeater"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
