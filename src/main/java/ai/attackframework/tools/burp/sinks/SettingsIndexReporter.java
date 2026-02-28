package ai.attackframework.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import ai.attackframework.tools.burp.utils.Version;
import ai.attackframework.tools.burp.utils.ExportStats;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;

/**
 * Pushes Burp project and user settings to the settings index when export is
 * running and "Settings" is selected. Initial push on Start; thereafter only
 * pushes when a change is detected (scheduler checks every 30 seconds). Each
 * push sends the full config and logs a short success/failure message at info
 * level.
 */
public final class SettingsIndexReporter {

    private static final int INTERVAL_SECONDS = 30;
    private static final String SETTINGS_INDEX = IndexNaming.INDEX_PREFIX + "-settings";
    private static final String SCHEMA_VERSION = "1";
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private static volatile ScheduledExecutorService scheduler;
    private static volatile String lastPushedHash;
    private static final ObjectMapper JSON = new ObjectMapper();

    private SettingsIndexReporter() {}

    /**
     * Pushes one settings snapshot immediately (e.g. initial push on Start).
     * Always pushes and logs; does not compare to last pushed hash. Safe to call
     * from any thread. No-op if export is not running, OpenSearch URL is blank,
     * or Settings is not in the selected data sources.
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SETTINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            String projectJson = api.burpSuite().exportProjectOptionsAsJson();
            String userJson = api.burpSuite().exportUserOptionsAsJson();
            ConfigState.State state = RuntimeConfig.getState();
            Map<String, Object> doc = buildSettingsDoc(api, projectJson, userJson, state);
            if (doc == null) {
                return;
            }
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, SETTINGS_INDEX, doc);
            if (ok) {
                ExportStats.recordSuccess("settings", 1);
                lastPushedHash = hashSettingsForEnabled(state, projectJson, userJson);
                Logger.logDebug("Settings index: snapshot pushed successfully.");
            } else {
                ExportStats.recordFailure("settings", 1);
                ExportStats.recordLastError("settings", "Settings index push failed");
                Logger.logDebug("Settings index: push failed (index request did not succeed).");
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            ExportStats.recordFailure("settings", 1);
            ExportStats.recordLastError("settings", msg);
            Logger.logDebug("Settings index: push failed: " + msg);
        }
    }

    /**
     * Starts the 30-second change-check scheduler. Does not perform an initial
     * push (caller must call {@link #pushSnapshotNow()} once on Start). Safe to
     * call from any thread.
     */
    public static void start() {
        if (scheduler != null) {
            return;
        }
        synchronized (SettingsIndexReporter.class) {
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "attackframework-settings-reporter");
                t.setDaemon(true);
                return t;
            });
            exec.scheduleAtFixedRate(
                    SettingsIndexReporter::pushSnapshotIfChanged,
                    INTERVAL_SECONDS,
                    INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
            scheduler = exec;
        }
    }

    /**
     * Called by the scheduler. Pushes only when current settings hash differs
     * from last pushed; logs at info level when a push is performed.
     */
    static void pushSnapshotIfChanged() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            String baseUrl = RuntimeConfig.openSearchUrl();
            if (baseUrl == null || baseUrl.isBlank()) {
                return;
            }
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SETTINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            String projectJson = api.burpSuite().exportProjectOptionsAsJson();
            String userJson = api.burpSuite().exportUserOptionsAsJson();
            ConfigState.State state = RuntimeConfig.getState();
            String currentHash = hashSettingsForEnabled(state, projectJson, userJson);
            if (currentHash.equals(lastPushedHash)) {
                return;
            }
            Map<String, Object> doc = buildSettingsDoc(api, projectJson, userJson, state);
            if (doc == null) {
                return;
            }
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, SETTINGS_INDEX, doc);
            if (ok) {
                ExportStats.recordSuccess("settings", 1);
                lastPushedHash = currentHash;
                Logger.logDebug("Settings index: snapshot pushed successfully (change detected).");
            } else {
                ExportStats.recordFailure("settings", 1);
                ExportStats.recordLastError("settings", "Settings index push failed");
                Logger.logDebug("Settings index: push failed (index request did not succeed).");
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            ExportStats.recordFailure("settings", 1);
            ExportStats.recordLastError("settings", msg);
            Logger.logDebug("Settings index: push failed: " + msg);
        }
    }

    private static String hashSettings(String projectJson, String userJson) {
        String combined = (projectJson != null ? projectJson : "") + "\n" + (userJson != null ? userJson : "");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(combined.hashCode());
        }
    }

    /** Hash only the enabled settings parts for change detection. */
    private static String hashSettingsForEnabled(ConfigState.State state, String projectJson, String userJson) {
        var sub = state != null && state.settingsSub() != null ? state.settingsSub() : java.util.List.<String>of();
        String projectPart = sub.contains(ConfigKeys.SRC_SETTINGS_PROJECT) ? (projectJson != null ? projectJson : "") : "";
        String userPart = sub.contains(ConfigKeys.SRC_SETTINGS_USER) ? (userJson != null ? userJson : "") : "";
        return hashSettings(projectPart, userPart);
    }

    private static Map<String, Object> buildSettingsDoc(MontoyaApi api, String projectOptionsJson, String userOptionsJson, ConfigState.State state) {
        String projectId;
        try {
            projectId = api.project().id();
        } catch (Exception e) {
            return null;
        }
        var sub = state != null && state.settingsSub() != null ? state.settingsSub() : java.util.List.<String>of();
        Map<String, Object> settingsProject = sub.contains(ConfigKeys.SRC_SETTINGS_PROJECT) ? parseJsonToMap(projectOptionsJson) : Map.of();
        Map<String, Object> settingsUser = sub.contains(ConfigKeys.SRC_SETTINGS_USER) ? parseJsonToMap(userOptionsJson) : Map.of();

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("project_id", projectId != null ? projectId : "");
        doc.put("settings_project", settingsProject != null ? settingsProject : Map.of());
        doc.put("settings_user", settingsUser != null ? settingsUser : Map.of());
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", SCHEMA_VERSION);
        meta.put("extension_version", Version.get());
        meta.put("indexed_at", Instant.now().toString());
        doc.put("document_meta", meta);
        return doc;
    }

    private static Map<String, Object> parseJsonToMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> map = JSON.readValue(json, MAP_TYPE);
            return map != null ? map : Map.of();
        } catch (Exception e) {
            return Map.of();
        }
    }
}
