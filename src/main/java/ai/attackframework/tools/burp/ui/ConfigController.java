package ai.attackframework.tools.burp.ui;

import ai.attackframework.tools.burp.sinks.OpenSearchSink;
import ai.attackframework.tools.burp.sinks.OpenSearchSink.IndexResult;
import ai.attackframework.tools.burp.utils.FileUtil;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.Logger;
import ai.attackframework.tools.burp.utils.config.ConfigJsonMapper;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.opensearch.OpenSearchClientWrapper;

import javax.swing.SwingWorker;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates config actions (files, OpenSearch, indexes, import/export/save).
 *
 * <p>Threading: long-running work (filesystem, network, index creation) is executed on
 * {@link SwingWorker}s. Save is synchronous because it only composes JSON and logs a small payload.</p>
 *
 * <p>Error handling: exceptions are converted into concise user-facing status messages via {@link Ui}
 * and are also logged through {@link Logger}.</p>
 */
public record ConfigController(Ui ui, FilePorts files, OpenSearchPorts os, IndexNamingPorts naming) {

    private static final String ERR_PREFIX = "✖ Error: ";

    /** UI callback surface implemented by the hosting panel. */
    public interface Ui {
        void onFileStatus(String message);
        void onOpenSearchStatus(String message);
        void onAdminStatus(String message);
        void onImportResult(ConfigState.State state);
    }

    /** File operations (abstracted for unit tests). */
    public interface FilePorts {
        List<FileUtil.CreateResult> ensureJsonFiles(String root, List<String> jsonNames);
        void writeStringCreateDirs(Path out, String content) throws IOException;
        String readString(Path in) throws IOException;
    }

    /** OpenSearch operations (abstracted for unit tests). */
    public interface OpenSearchPorts {
        OpenSearchClientWrapper.OpenSearchStatus testConnection(String url);
        List<IndexResult> createSelectedIndexes(String url, List<String> selectedSources);
    }

    /** Naming helpers (abstracted for unit tests). */
    public interface IndexNamingPorts {
        List<String> computeIndexBaseNames(List<String> selectedSources);
        List<String> toJsonFileNames(List<String> baseNames);
    }

    /** Convenience constructor wiring production adapters. */
    public ConfigController(Ui ui) {
        this(ui,
                new FilePorts() {
                    @Override public List<FileUtil.CreateResult> ensureJsonFiles(String root, List<String> jsonNames) {
                        return FileUtil.ensureJsonFiles(root, jsonNames);
                    }
                    @Override public void writeStringCreateDirs(Path out, String content) throws IOException {
                        FileUtil.writeStringCreateDirs(out, content);
                    }
                    @Override public String readString(Path in) throws IOException {
                        return FileUtil.readString(in);
                    }
                },
                new OpenSearchPorts() {
                    @Override public OpenSearchClientWrapper.OpenSearchStatus testConnection(String url) {
                        return OpenSearchClientWrapper.safeTestConnection(url);
                    }
                    @Override public List<IndexResult> createSelectedIndexes(String url, List<String> selectedSources) {
                        return OpenSearchSink.createSelectedIndexes(url, selectedSources);
                    }
                },
                new IndexNamingPorts() {
                    @Override public List<String> computeIndexBaseNames(List<String> selectedSources) {
                        return IndexNaming.computeIndexBaseNames(selectedSources);
                    }
                    @Override public List<String> toJsonFileNames(List<String> baseNames) {
                        return IndexNaming.toJsonFileNames(baseNames);
                    }
                }
        );
    }

    public void createFilesAsync(String root, List<String> selectedSources) {
        var worker = new SwingWorker<List<FileUtil.CreateResult>, Void>() {
            @Override protected List<FileUtil.CreateResult> doInBackground() {
                List<String> baseNames = naming.computeIndexBaseNames(selectedSources);
                List<String> jsonNames = naming.toJsonFileNames(baseNames);
                return files.ensureJsonFiles(root, jsonNames);
            }
            @Override protected void done() {
                try {
                    List<FileUtil.CreateResult> results = get();
                    ui.onFileStatus(summarizeFileCreateResults(results));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onFileStatus("✖ File creation interrupted");
                    Logger.logError("File creation interrupted: " + ie.getMessage());
                } catch (Exception ex) {
                    ui.onFileStatus(ERR_PREFIX + ex.getMessage());
                    Logger.logError("File creation error: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    public void testConnectionAsync(String url) {
        ui.onOpenSearchStatus("Testing ...");
        var worker = new SwingWorker<OpenSearchClientWrapper.OpenSearchStatus, Void>() {
            @Override protected OpenSearchClientWrapper.OpenSearchStatus doInBackground() {
                return os.testConnection(url);
            }
            @Override protected void done() {
                try {
                    OpenSearchClientWrapper.OpenSearchStatus status = get();
                    if (status.success()) {
                        String msg = status.message() + " (" + status.distribution() + " v" + status.version() + ")";
                        ui.onOpenSearchStatus(msg);
                        Logger.logInfo("OpenSearch connection successful: " + msg + " at " + url);
                    } else {
                        ui.onOpenSearchStatus("✖ " + status.message());
                        Logger.logError("OpenSearch connection failed: " + status.message());
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onOpenSearchStatus("✖ Connection test interrupted");
                    Logger.logError("OpenSearch connection interrupted: " + ie.getMessage());
                } catch (Exception ex) {
                    ui.onOpenSearchStatus(ERR_PREFIX + ex.getMessage());
                    Logger.logError("OpenSearch connection error: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    public void createIndexesAsync(String url, List<String> selectedSources) {
        ui.onOpenSearchStatus("Creating indexes . . .");
        var worker = new SwingWorker<List<IndexResult>, Void>() {
            @Override protected List<IndexResult> doInBackground() {
                return os.createSelectedIndexes(url, selectedSources);
            }
            @Override protected void done() {
                try {
                    List<IndexResult> results = get();
                    ui.onOpenSearchStatus(summarizeIndexResults(results));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onOpenSearchStatus("✖ Index creation interrupted");
                    Logger.logError("Index creation interrupted: " + ie.getMessage());
                } catch (Exception ex) {
                    ui.onOpenSearchStatus(ERR_PREFIX + ex.getMessage());
                    Logger.logError("Index creation error: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    public void exportConfigAsync(Path out, String json) {
        var worker = new SwingWorker<Path, Void>() {
            @Override protected Path doInBackground() throws Exception {
                files.writeStringCreateDirs(out, json);
                return out;
            }
            @Override protected void done() {
                try {
                    Path p = get();
                    String msg = "Exported to " + p.toAbsolutePath();
                    ui.onAdminStatus(msg);
                    Logger.logInfo("Config exported to " + p.toAbsolutePath());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onAdminStatus("✖ Export interrupted");
                    Logger.logError("Export interrupted: " + ie.getMessage());
                } catch (Exception ex) {
                    ui.onAdminStatus(ERR_PREFIX + ex.getMessage());
                    Logger.logError("Export error: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    public void importConfigAsync(Path in) {
        var worker = new SwingWorker<ConfigState.State, Void>() {
            @Override protected ConfigState.State doInBackground() throws Exception {
                String json = files.readString(in);
                return ConfigJsonMapper.parse(json);
            }
            @Override protected void done() {
                try {
                    ConfigState.State state = get();
                    ui.onImportResult(state);
                    String msg = "Imported from " + in.toAbsolutePath();
                    ui.onAdminStatus(msg);
                    Logger.logInfo("Config imported from " + in.toAbsolutePath());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    ui.onAdminStatus("✖ Import interrupted");
                    Logger.logError("Import interrupted: " + ie.getMessage());
                } catch (Exception ex) {
                    ui.onAdminStatus(ERR_PREFIX + ex.getMessage());
                    Logger.logError("Import error: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    /**
     * Save synchronously: build JSON and log it, then update the admin status.
     * This preserves the original semantics expected by headless tests that capture logs.
     *
     * @param state typed state composed by the panel
     */
    public void saveAsync(ConfigState.State state) {
        try {
            String json = ConfigJsonMapper.build(state);
            Logger.logInfo("Saving config ...");
            Logger.logInfo(json);
            ui.onAdminStatus("Saved!");
        } catch (Exception ex) {
            ui.onAdminStatus(ERR_PREFIX + ex.getMessage());
            Logger.logError("Save error: " + ex.getMessage());
        }
    }

    /* ------------------- summary helpers (status text) ------------------- */

    private static String summarizeFileCreateResults(List<FileUtil.CreateResult> results) {
        List<String> created = new ArrayList<>();
        List<String> exists  = new ArrayList<>();
        List<String> failed  = new ArrayList<>();
        for (FileUtil.CreateResult r : results) {
            switch (r.status()) {
                case CREATED -> created.add(r.path().toString());
                case EXISTS  -> exists.add(r.path().toString());
                case FAILED  -> failed.add(r.path().toString() + " — " + r.error());
            }
        }
        StringBuilder sb = new StringBuilder();
        if (!created.isEmpty()) {
            sb.append(created.size() == 1 ? "File created:\n  " : "Files created:\n  ")
                    .append(String.join("\n  ", created)).append("\n");
        }
        if (!exists.isEmpty()) {
            sb.append(exists.size() == 1 ? "File already existed:\n  " : "Files already existed:\n  ")
                    .append(String.join("\n  ", exists)).append("\n");
        }
        if (!failed.isEmpty()) {
            sb.append(failed.size() == 1 ? "File creation failed:\n  " : "File creations failed:\n  ")
                    .append(String.join("\n  ", failed)).append("\n");
        }
        return sb.toString().trim();
    }

    /** Summarizes index results and, on failure, appends a concise reason. */
    private static String summarizeIndexResults(List<IndexResult> results) {
        List<String> created = new ArrayList<>();
        List<String> exists  = new ArrayList<>();
        List<String> failed  = new ArrayList<>();
        String firstReason = null;

        for (IndexResult r : results) {
            switch (r.status()) {
                case CREATED -> created.add(r.fullName());
                case EXISTS  -> exists.add(r.fullName());
                case FAILED  -> {
                    failed.add(r.fullName());
                    if (firstReason == null && r.error() != null && !r.error().isBlank()) {
                        firstReason = r.error();
                    }
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        if (!created.isEmpty()) {
            sb.append(created.size() == 1 ? "Index created:\n  " : "Indexes created:\n  ")
                    .append(String.join("\n  ", created)).append("\n");
        }
        if (!exists.isEmpty()) {
            sb.append(exists.size() == 1 ? "Index already existed:\n  " : "Indexes already existed:\n  ")
                    .append(String.join("\n  ", exists)).append("\n");
        }
        if (!failed.isEmpty()) {
            sb.append(failed.size() == 1 ? "Index failed:\n  " : "Indexes failed:\n  ")
                    .append(String.join("\n  ", failed)).append("\n");
            if (firstReason != null) {
                sb.append("Reason: ").append(firstReason).append("\n");
            }
        }
        return sb.toString().trim();
    }
}
