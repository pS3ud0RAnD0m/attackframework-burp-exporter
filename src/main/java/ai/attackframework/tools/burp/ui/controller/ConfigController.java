package ai.attackframework.tools.burp.ui.controller;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.FileUtil.CreateResult;
import ai.attackframework.tools.burp.utils.FileUtil.Status;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Coordinates long-running operations for the Config UI: export/import, file creation,
 * and OpenSearch connectivity/index management. UI updates are posted to the EDT.
 */
public final class ConfigController {

    private static final String TEST_FAILED = "Test failed: ";

    /** UI callback surface implemented by ConfigPanel. */
    public interface Ui {
        void onFileStatus(String message);
        void onOpenSearchStatus(String message);
        void onAdminStatus(String message);
    }

    private final Ui ui;

    public ConfigController(Ui ui) {
        this.ui = Objects.requireNonNull(ui, "ui");
    }

    /* ---------------- Export / Import / Save ---------------- */

    public void exportConfigAsync(Path out, String json) {
        Logger.logInfo ("[ConfigPanel] exportConfigAsync invoked; out=" + out);
        Logger.logInfo ("[ConfigPanel] exportConfigAsync payload=" + json);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    FileUtil.writeStringCreateDirs(out, json);
                    return "Exported configuration to: " + out;
                } catch (Exception e) {
                    return "Export failed: " + rootMessage(e);
                }
            }
            @Override protected void done() {
                try {
                    ui.onAdminStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onAdminStatus("Export interrupted.");
                } catch (Exception ex) {
                    ui.onAdminStatus("Export failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    public void importConfigAsync(Path in) {
        Logger.logInfo ("[ConfigPanel] importConfigAsync invoked; in=" + in);
        new SwingWorker<ConfigState.State, Void>() {
            @Override protected ConfigState.State doInBackground() throws Exception {
                String json = FileUtil.readString(in);
                Logger.logInfo ("[ConfigPanel] importConfigAsync payload=" + json);
                return ConfigJsonMapper.parse(json);
            }
            @Override protected void done() {
                try {
                    ConfigState.State state = get();
                    ui.onAdminStatus("Imported configuration from: " + in);
                    SwingUtilities.invokeLater(() -> {
                        if (ui instanceof ai.attackframework.tools.burp.ui.ConfigPanel p) {
                            p.onImportResult(state);
                        }
                    });
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onAdminStatus("Import interrupted.");
                } catch (Exception ex) {
                    ui.onAdminStatus("Import failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    public void saveAsync(ConfigState.State state) {
        Logger.logInfo ("[ConfigPanel] saveAsync invoked");
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    String json = ConfigJsonMapper.build(state);
                    Logger.logInfo ("[ConfigPanel] saveAsync payload=" + json);
                    return "Saved.";
                } catch (Exception ex) {
                    Logger.logError("[ConfigPanel] Save failed: " + rootMessage(ex));
                    return "Save failed: " + rootMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    ui.onAdminStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onAdminStatus("Save interrupted.");
                } catch (Exception ex) {
                    ui.onAdminStatus("Save failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    /* ---------------- Files sink ---------------- */

    public void createFilesAsync(String rootDir, List<String> selectedSources) {
        Logger.logInfo("[ConfigPanel] createFilesAsync invoked; rootDir=" + rootDir
                + ", selectedSources=" + selectedSources);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    List<String> bases     = IndexNaming.computeIndexBaseNames(selectedSources);
                    List<String> jsonNames = IndexNaming.toJsonFileNames(bases);
                    Logger.logInfo("[ConfigPanel] createFilesAsync JSON names=" + jsonNames);
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
                } catch (Exception ex) {
                    ui.onFileStatus("Create files failed: " + rootMessage(ex));
                }
            }
        }.execute();
    }

    /* ---------------- OpenSearch: test + create indexes ---------------- */

    public void testConnectionAsync(String url) {
        Logger.logInfo("[ConfigPanel] testConnectionAsync invoked; url=" + url);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    var s = OpenSearchClientWrapper.safeTestConnection(url);
                    Logger.logInfo("[ConfigPanel] testConnection result: success=" + s.success()
                            + ", message=" + s.message());
                    if (s.success()) {
                        return "Connected to OpenSearch: " + s.distribution() + " " + s.version();
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
                } catch (Exception ex) {
                    ui.onOpenSearchStatus(TEST_FAILED + rootMessage(ex));
                }
            }
        }.execute();
    }

    public void createIndexesAsync(String url, List<String> selectedSources) {
        Logger.logInfo("[ConfigPanel] createIndexesAsync invoked; url=" + url
                + ", selectedSources=" + selectedSources);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                try {
                    List<IndexResult> results = OpenSearchSink.createSelectedIndexes(url, selectedSources);
                    Logger.logInfo("[ConfigPanel] createIndexesAsync results=" + results);
                    return formatCreateIndexesResult(results);
                } catch (Exception ex) {
                    Logger.logError("[ConfigPanel] Create indexes failed: " + rootMessage(ex));
                    return "Create indexes failed: " + rootMessage(ex);
                }
            }
            @Override protected void done() {
                try {
                    ui.onOpenSearchStatus(get());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onOpenSearchStatus("Create indexes interrupted.");
                } catch (Exception ex) {
                    ui.onOpenSearchStatus("Create indexes failed: " + rootMessage(ex));
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
            if (r.status() == Status.CREATED) {
                created.add(p);
            } else if (r.status() == Status.EXISTS) {
                existed.add(p);
            } else {
                failed.add(p);
                if (firstError == null && r.error() != null) firstError = r.error();
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

    private static String formatCreateIndexesResult(List<IndexResult> results) {
        List<String> created = new ArrayList<>();
        List<String> existed = new ArrayList<>();
        List<String> failed  = new ArrayList<>();
        String firstReason = null;

        for (IndexResult r : results) {
            switch (r.status()) {
                case CREATED -> created.add(r.fullName());
                case EXISTS  -> existed.add(r.fullName());
                case FAILED  -> {
                    failed.add(r.fullName());
                    if (firstReason == null && r.error() != null) firstReason = r.error();
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        if (!created.isEmpty()) {
            sb.append(created.size() == 1 ? "Created index:\n  " : "Created indexes:\n  ")
                    .append(String.join("\n  ", created)).append('\n');
        }
        if (!existed.isEmpty()) {
            sb.append(existed.size() == 1 ? "Index already existed:\n  " : "Indexes already existed:\n  ")
                    .append(String.join("\n  ", existed)).append('\n');
        }
        if (!failed.isEmpty()) {
            sb.append(failed.size() == 1 ? "Index failed:\n  " : "Indexes failed:\n  ")
                    .append(String.join("\n  ", failed)).append('\n');
            if (firstReason != null) sb.append("Reason: ").append(firstReason).append('\n');
        }
        return sb.toString().trim();
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) c = c.getCause();
        return c.getMessage() == null ? c.toString() : c.getMessage();
    }
}
