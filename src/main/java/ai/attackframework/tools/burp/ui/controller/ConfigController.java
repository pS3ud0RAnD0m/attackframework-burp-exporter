package ai.attackframework.tools.burp.ui.controller;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.FileUtil.CreateResult;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.DiskSpaceGuard;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Coordinates long-running operations for the Config UI: export/import, file creation,
 * and OpenSearch connectivity/index management.
 * <p>
 * Each async method runs work on a {@link SwingWorker} background thread and marshals UI updates to
 * the EDT via the {@link Ui} callbacks. Callers may invoke methods from any thread.
 */
public final class ConfigController {

    private static final String TEST_FAILED = "Test failed: ";

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

    /* ---------------- Files sink ---------------- */

    /**
     * Ensures JSON export files exist for the selected sources under the given root directory.
     * <p>
     * Work executes on a background thread; completion status is posted to
     * {@link Ui#onFileStatus} on the EDT.
     *
     * @param rootDir root directory for generated files
     * @param selectedSources data sources to include
     */
    public void createFilesAsync(String rootDir, List<String> selectedSources) {
        Logger.logDebug("[ConfigPanel] createFilesAsync invoked; rootDir=" + rootDir
                + ", selectedSources=" + selectedSources);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    List<String> bases     = IndexNaming.computeIndexBaseNames(selectedSources);
                    List<String> jsonNames = IndexNaming.toJsonFileNames(bases);
                    Logger.logDebug("[ConfigPanel] createFilesAsync JSON names=" + jsonNames);
                    List<CreateResult> results = FileUtil.ensureJsonFiles(rootDir, jsonNames);
                    return formatCreateFilesResult(results);
                } catch (Exception ex) {
                    Logger.logError("[ConfigPanel] Create files failed: " + rootMessage(ex));
                    return "Create files failed: " + rootMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    ui.onFileStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onFileStatus("Create files interrupted.");
                } catch (ExecutionException ex) {
                    ui.onFileStatus("Create files failed: " + rootMessage(ex));
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
                    if (s.success()) {
                        return "Connected to: " + s.distribution() + " " + s.version();
                    } else {
                        return TEST_FAILED + (s.message() == null ? "Unknown error" : s.message());
                    }
                } catch (Exception ex) {
                    Logger.logError("[ConfigPanel] Test connection failed: " + rootMessage(ex));
                    return TEST_FAILED + rootMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    ui.onOpenSearchStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onOpenSearchStatus(TEST_FAILED + "interrupted.");
                } catch (ExecutionException ex) {
                    ui.onOpenSearchStatus(TEST_FAILED + rootMessage(ex));
                }
            }
        }.execute();
    }

    /* ---------------- helpers ---------------- */

    private static String formatCreateFilesResult(List<CreateResult> results) {
        List<String> created = new ArrayList<>();
        List<String> existed = new ArrayList<>();
        List<String> failed  = new ArrayList<>();
        String firstError = null;

        for (CreateResult r : results) {
            String p = r.path().toString();
            switch (r.status()) {
                case CREATED -> created.add(p);
                case EXISTS -> existed.add(p);
                case FAILED -> {
                    failed.add(p);
                    if (firstError == null && r.error() != null) {
                        firstError = r.error();
                    }
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        if (!created.isEmpty()) {
            sb.append(created.size() == 1 ? "Created file:\n  " : "Created files:\n  ")
                    .append(String.join("\n  ", created)).append('\n');
        }
        if (!existed.isEmpty()) {
            sb.append(existed.size() == 1 ? "File already existed:\n  " : "Files already existed:\n  ")
                    .append(String.join("\n  ", existed)).append('\n');
        }
        if (!failed.isEmpty()) {
            sb.append(failed.size() == 1 ? "File failed:\n  " : "Files failed:\n  ")
                    .append(String.join("\n  ", failed)).append('\n');
            if (firstError != null) sb.append("Reason: ").append(firstError).append('\n');
        }
        return sb.toString().trim();
    }

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
