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
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Coordinates long-running operations for the Config UI: export/import and OpenSearch
 * connectivity/index management.
 * <p>
 * Each async method runs work on a {@link SwingWorker} background thread and marshals UI updates to
 * the EDT via the {@link Ui} callbacks. Callers may invoke methods from any thread.
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

    /* ---------------- Export / Import / Save ---------------- */

    /**
     * Writes the provided config JSON to disk asynchronously.
     * <p>
     * Work is performed on a background thread; status is published to {@link Ui#onControlStatus}
     * on the EDT.
     *
     * @param out  destination path (will be created with parent directories)
     * @param json serialized configuration payload
     */
    public void exportConfigAsync(Path out, String json) {
        Logger.logDebug("[ConfigPanel] exportConfigAsync invoked; out=" + out);
        Logger.logInfoPanelOnly("[ConfigPanel] exportConfigAsync payload prepared");
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
                    ui.onControlStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onControlStatus("Export interrupted.");
                } catch (ExecutionException ex) {
                    ui.onControlStatus("Export failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    /**
     * Reads and parses a configuration file asynchronously.
     * <p>
     * On success, forwards the parsed state to the UI on the EDT and reports status through
     * {@link Ui#onControlStatus}. Errors are surfaced as status strings.
     *
     * @param in config file to load
     */
    public void importConfigAsync(Path in) {
        Logger.logDebug("[ConfigPanel] importConfigAsync invoked; in=" + in);
        new SwingWorker<ConfigState.State, Void>() {
            @Override protected ConfigState.State doInBackground() throws Exception {
                String json = FileUtil.readString(in);
                Logger.logInfoPanelOnly("[ConfigPanel] importConfigAsync payload loaded");
                return ConfigJsonMapper.parse(json);
            }
            @Override protected void done() {
                try {
                    ConfigState.State state = get();
                    ui.onControlStatus("Imported configuration from: " + in);
                    SwingUtilities.invokeLater(() -> {
                        if (ui instanceof ai.attackframework.tools.burp.ui.ConfigPanel p) {
                            p.onImportResult(state);
                        }
                    });
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onControlStatus("Import interrupted.");
                } catch (ExecutionException ex) {
                    ui.onControlStatus("Import failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    /**
     * Serializes the current configuration to JSON asynchronously (no I/O).
     * <p>
     * Status is delivered to {@link Ui#onControlStatus} on the EDT. This is a lightweight operation
     * but remains async for consistency with other actions.
     *
     * @param state configuration to serialize
     */
    public void saveAsync(ConfigState.State state) {
        Logger.logDebug("[ConfigPanel] saveAsync invoked");
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    ConfigJsonMapper.build(state);
                    Logger.logInfoPanelOnly("[ConfigPanel] saveAsync payload updated");
                    return "Saved.";
                } catch (Exception ex) {
                    Logger.logError("[ConfigPanel] Save failed: " + rootMessage(ex));
                    return "Save failed: " + userFacingMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    ui.onControlStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onControlStatus("Save interrupted.");
                } catch (ExecutionException ex) {
                    ui.onControlStatus("Save failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    /* ---------------- OpenSearch: test + create indexes ---------------- */

    /**
     * Tests connectivity to an OpenSearch cluster asynchronously.
     * <p>
     * The result message is sent to {@link Ui#onOpenSearchStatus} on the EDT.
     * Uses current RuntimeConfig for credentials and insecure-SSL (caller should call
     * updateRuntimeConfig / buildCurrentState before this so the checkbox and current session auth apply).
     *
     * @param url base URL of the OpenSearch cluster
     */
    public void testConnectionAsync(String url) {
        Logger.logDebug("[ConfigPanel] testConnectionAsync invoked; url=" + url);
        String user = RuntimeConfig.openSearchUser();
        String pass = RuntimeConfig.openSearchPassword();
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    var s = OpenSearchClientWrapper.safeTestConnection(url, user, pass);
                    Logger.logDebug("[ConfigPanel] testConnection result: success=" + s.success()
                            + ", message=" + s.message());
                    return s.formattedStatus();
                } catch (Exception ex) {
                    Logger.logError("[ConfigPanel] Test connection failed: " + rootMessage(ex));
                    return "Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\nOpenSearch version: unknown\nDetails: "
                            + rootMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    ui.onOpenSearchStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onOpenSearchStatus("Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\nOpenSearch version: unknown\nDetails: interrupted.");
                } catch (ExecutionException ex) {
                    ui.onOpenSearchStatus("Connection: Failed\nAuthentication: Not tested\nTrust: Not tested\nOpenSearch version: unknown\nDetails: "
                            + rootMessage(ex));
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
}
