package ai.attackframework.tools.burp.ui.controller;

import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.DiskSpaceGuard;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigParseResult;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Coordinates long-running operations for the Config UI.
 *
 * <p>This controller handles config export/import plus OpenSearch connectivity and index
 * management. Each async method runs work on a {@link SwingWorker} background thread and marshals
 * UI updates to the EDT via the {@link Ui} callbacks. Callers may invoke these methods from any
 * thread.</p>
 */
public final class ConfigController {

    /** UI callback surface implemented by ConfigPanel. */
    public interface Ui {
        void onFileStatus(String message);
        void onOpenSearchStatus(String message);
        void onControlStatus(String message);
    }

    private final Ui ui;

    public ConfigController(Ui ui) {
        this.ui = Objects.requireNonNull(ui, "ui");
    }

    /* ---------------- Export / Import ---------------- */

    /**
     * Writes the provided config JSON to disk asynchronously.
     *
     * <p>Work is performed on a background thread; status is published to
     * {@link Ui#onControlStatus} on the EDT.</p>
     *
     * @param out  destination path (will be created with parent directories)
     * @param json serialized configuration payload
     */
    public void exportConfigAsync(Path out, String json) {
        Logger.logDebug("[Config] Export requested: " + out);
        Logger.logInfoPanelOnly("[Config] Exporting configuration to " + out + ".");
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    FileUtil.writeStringCreateDirs(out, json);
                    return "Exported configuration to: " + out;
                } catch (java.io.IOException | RuntimeException e) {
                    return "Export failed: " + userFacingMessage(e);
                }
            }
            @Override protected void done() {
                try {
                    String status = get();
                    ui.onControlStatus(status);
                    if (status.startsWith("Exported configuration")) {
                        Logger.logInfoPanelOnly("[Config] " + status);
                    } else {
                        Logger.logErrorPanelOnly("[Config] " + status);
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onControlStatus("Export interrupted.");
                    Logger.logWarnPanelOnly("[Config] Export interrupted.");
                } catch (ExecutionException ex) {
                    String status = "Export failed: " + rootMessage(ex);
                    ui.onControlStatus(status);
                    Logger.logErrorPanelOnly("[Config] " + status);
                }
            }
        }.execute();
    }

    /**
     * Reads and parses a configuration file asynchronously.
     *
     * <p>On success, forwards the parsed state to the UI on the EDT and reports status through
     * {@link Ui#onControlStatus}. Unrecognized keys and values are skipped with INFO log lines and
     * a multi-line status summary; hard failures (invalid JSON, legacy flat sinks, invalid auth)
     * surface as error status only.</p>
     *
     * <p>Caller thread: {@code SwingWorker} background thread for I/O and parse; UI callbacks on
     * the EDT.</p>
     *
     * @param in config file to load
     */
    public void importConfigAsync(Path in) {
        Logger.logDebug("[Config] Import requested: " + in);
        new SwingWorker<ConfigParseResult, Void>() {
            @Override protected ConfigParseResult doInBackground() throws Exception {
                String json = FileUtil.readString(in);
                Logger.logInfoPanelOnly("[Config] Importing configuration from " + in + ".");
                return ConfigJsonMapper.parse(json);
            }
            @Override protected void done() {
                try {
                    ConfigParseResult result = get();
                    ConfigState.State state = result.state();
                    String status = result.report().formatControlStatusSummary(in);
                    ui.onControlStatus(status);
                    for (String line : result.report().formatLogLines(20)) {
                        Logger.logInfoPanelOnly(line);
                    }
                    if (result.report().isEmpty()) {
                        Logger.logInfoPanelOnly("[Config] Imported configuration from " + in + ".");
                    }
                    SwingUtilities.invokeLater(() -> {
                        if (ui instanceof ai.attackframework.tools.burp.ui.ConfigPanel p) {
                            p.onImportResult(state);
                        }
                    });
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onControlStatus("Import interrupted.");
                    Logger.logWarnPanelOnly("[Config] Import interrupted.");
                } catch (ExecutionException ex) {
                    String status = formatImportFailureStatus(ex);
                    ui.onControlStatus(status);
                    Logger.logErrorPanelOnly("[Config] " + status);
                }
            }
        }.execute();
    }

    /* ---------------- OpenSearch: test + create indexes ---------------- */

    /**
     * Tests connectivity to an OpenSearch cluster asynchronously.
     *
     * <p>The result message is sent to {@link Ui#onOpenSearchStatus} on the EDT. This method uses
     * the current {@link RuntimeConfig} credentials and TLS mode, so callers should update runtime
     * config before invoking it.</p>
     *
     * @param url base URL of the OpenSearch cluster
     */
    public void testConnectionAsync(String url) {
        Logger.logDebug("[Config] OpenSearch test connection requested: " + url);
        String user = RuntimeConfig.openSearchUser();
        String pass = RuntimeConfig.openSearchPassword();
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    var s = OpenSearchClientWrapper.safeTestConnection(url, user, pass);
                    Logger.logDebug("[Config] OpenSearch test result: success=" + s.success()
                            + ", message=" + s.message());
                    return s.formattedStatus();
                } catch (Exception ex) {
                    Logger.logError("[Config] OpenSearch test connection failed: " + rootMessage(ex));
                    return "Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\nOpenSearch version: unknown\nDetails: "
                            + rootMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    String status = get();
                    ui.onOpenSearchStatus(status);
                    if (status.startsWith("Connection: Success")) {
                        Logger.logInfoPanelOnly("[OpenSearch] Test connection result\n" + status);
                    } else {
                        Logger.logWarnPanelOnly("[OpenSearch] Test connection result\n" + status);
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    String status = "Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\nOpenSearch version: unknown\nDetails: interrupted.";
                    ui.onOpenSearchStatus(status);
                    Logger.logWarnPanelOnly("[OpenSearch] Test connection interrupted\n" + status);
                } catch (ExecutionException ex) {
                    String status = "Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\nOpenSearch version: unknown\nDetails: "
                            + rootMessage(ex);
                    ui.onOpenSearchStatus(status);
                    Logger.logWarnPanelOnly("[OpenSearch] Test connection result\n" + status);
                }
            }
        }.execute();
    }

    /* ---------------- helpers ---------------- */

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) c = c.getCause();
        return c.getMessage() == null ? c.toString() : c.getMessage();
    }

    private static String userFacingMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) c = c.getCause();
        if (c instanceof DiskSpaceGuard.LowDiskSpaceException lowDisk) {
            return lowDisk.userMessage();
        }
        return c.getMessage() == null ? c.toString() : c.getMessage();
    }

    private static String formatImportFailureStatus(Throwable t) {
        String detail = userFacingMessage(t);
        if (detail.contains("sinks.files") || detail.contains("sinks.openSearch")) {
            return "Import failed: Sink settings must use nested 'sinks.files' and 'sinks.openSearch' objects "
                    + "(for example 'sinks.files.limits.totalEnabled'). Details: " + detail;
        }
        return "Import failed: " + detail;
    }
}
