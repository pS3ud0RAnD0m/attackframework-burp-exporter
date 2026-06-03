package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.testutils.TestPathSupport;
import ai.attackframework.tools.burp.utils.ControlStatusBridge;
import ai.attackframework.tools.burp.utils.FileExportStats;
import ai.attackframework.tools.burp.utils.IndexNaming;
import ai.attackframework.tools.burp.utils.config.ConfigKeys;
import ai.attackframework.tools.burp.utils.config.ConfigState;
import ai.attackframework.tools.burp.utils.config.RuntimeConfig;
import ai.attackframework.tools.burp.utils.export.ExportDocumentIdentity;
import ai.attackframework.tools.burp.utils.export.PreparedExportDocument;

class FileExportServiceTest {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @Test
    void emit_writesJsonlAndBulkNdjsonWithSharedStableId() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-service");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(prepared);

            String jsonl = Files.readString(root.resolve(indexName + ".jsonl"));
            String ndjson = Files.readString(root.resolve(indexName + ".ndjson"));

            assertThat(jsonl).contains(prepared.exportId());
            assertThat(ndjson).contains("\"_id\":\"" + prepared.exportId() + "\"");
            assertThat(ndjson).contains("\"export_id\":\"" + prepared.exportId() + "\"");
        });
    }

    @Test
    void prepare_returnsSameStableIdForSameLogicalDocument() throws Exception {
        withCleanup(() -> {
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");

            PreparedExportDocument first = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            assertThat(first.exportId()).isEqualTo(second.exportId());
        });
    }

    @Test
    void emit_keepsSingleFilePerFormat_andDoesNotRoll() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-single-file");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument first = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument("https://acme.com/api/2"));

            FileExportService.emit(first);
            FileExportService.emit(second);

            assertThat(root.resolve(indexName + ".jsonl")).exists();
            assertThat(root.resolve(indexName + ".ndjson")).exists();
            assertThat(root.resolve(indexName + "-0002.jsonl")).doesNotExist();
            assertThat(root.resolve(indexName + "-0002.ndjson")).doesNotExist();
        });
    }

    @Test
    void emit_writesNewlineTerminatedBulkNdjsonAndJsonlLines() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-newlines");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(prepared);

            String jsonl = Files.readString(root.resolve(indexName + ".jsonl"));
            String ndjson = Files.readString(root.resolve(indexName + ".ndjson"));

            assertThat(jsonl).endsWith("\n");
            assertThat(ndjson).endsWith("\n");
            assertThat(ndjson.lines().count()).isEqualTo(2);
        });
    }

    @Test
    void emit_writesJsonlAsDocumentOnlyLineAndPreservesStableIdAcrossRepeatedExports() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-jsonl-shape");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument first = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());

            FileExportService.emit(first);
            FileExportService.emit(second);

            List<String> jsonlLines = Files.readAllLines(root.resolve(indexName + ".jsonl"));
            assertThat(jsonlLines).hasSize(2);
            assertThat(jsonlLines.get(0)).startsWith("{");
            assertThat(jsonlLines.get(0)).doesNotContain("\"index\"");
            assertThat(jsonlLines.get(0)).contains("\"export_id\":\"" + first.exportId() + "\"");
            assertThat(jsonlLines.get(1)).contains("\"export_id\":\"" + second.exportId() + "\"");
            assertThat(first.exportId()).isEqualTo(second.exportId());
        });
    }

    @Test
    void emit_appendsToExistingExporterFiles_insteadOfTruncating() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-append-existing");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            Path jsonlPath = root.resolve(indexName + ".jsonl");
            Path ndjsonPath = root.resolve(indexName + ".ndjson");
            Files.writeString(jsonlPath, "{\"seed\":true}\n");
            Files.writeString(ndjsonPath, "{\"index\":{\"_id\":\"seed\"}}\n{\"seed\":true}\n");

            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            FileExportService.emit(prepared);

            List<String> jsonlLines = Files.readAllLines(jsonlPath);
            List<String> ndjsonLines = Files.readAllLines(ndjsonPath);
            assertThat(jsonlLines).hasSize(2);
            assertThat(jsonlLines.getFirst()).isEqualTo("{\"seed\":true}");
            assertThat(jsonlLines.getLast()).contains("\"export_id\":\"" + prepared.exportId() + "\"");
            assertThat(ndjsonLines).hasSize(4);
            assertThat(ndjsonLines.getFirst()).isEqualTo("{\"index\":{\"_id\":\"seed\"}}");
            assertThat(ndjsonLines.get(1)).isEqualTo("{\"seed\":true}");
            assertThat(ndjsonLines.get(2)).contains("\"_id\":\"" + prepared.exportId() + "\"");
            assertThat(ndjsonLines.get(3)).contains("\"export_id\":\"" + prepared.exportId() + "\"");
        });
    }

    @Test
    void emit_recordsFileStatsForIndexAndTrafficSource() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-stats");
            RuntimeConfig.updateState(fileExportState(root, true, Long.MAX_VALUE, false, 95));

            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            long beforeSuccess = FileExportStats.getSuccessCount("traffic");
            long beforeSource = FileExportStats.getTrafficToolTypeSuccessCount("PROXY");

            FileExportService.emit(prepared);

            assertThat(FileExportStats.getSuccessCount("traffic")).isEqualTo(beforeSuccess + 1);
            assertThat(FileExportStats.getTrafficToolTypeSuccessCount("PROXY")).isEqualTo(beforeSource + 1);
            assertThat(FileExportStats.getExportedBytes("traffic")).isGreaterThan(0L);
        });
    }

    @Test
    void emit_stopsAllFileExport_whenTotalCapIsHit() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-total-cap");
            PreparedExportDocument first = ExportDocumentIdentity.prepare(IndexNaming.indexNameForShortName("traffic"), "traffic", sampleDocument());
            PreparedExportDocument second = ExportDocumentIdentity.prepare(IndexNaming.indexNameForShortName("settings"), "settings",
                    sampleDocument("https://acme.com/settings"));

            long firstBytes = new JsonlFileSink(root, first.indexName()).estimateBytes(first)
                    + new BulkNdjsonFileSink(root, first.indexName()).estimateBytes(first);
            RuntimeConfig.updateState(fileExportState(root, true, firstBytes + 10L, false, 95));

            FileExportService.emit(first);
            FileExportService.emit(second);

            assertThat(root.resolve(first.indexName() + ".jsonl")).exists();
            assertThat(root.resolve(first.indexName() + ".ndjson")).exists();
            assertThat(root.resolve(second.indexName() + ".jsonl")).doesNotExist();
            assertThat(root.resolve(second.indexName() + ".ndjson")).doesNotExist();
        });
    }

    @Test
    void emit_countsExistingExporterFilesTowardCap_and_reportsOpenSearchContinues() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-existing-cap");
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            Path existingJsonl = root.resolve(indexName + ".jsonl");
            Files.writeString(existingJsonl, "{\"seed\":true}\n");

            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            long plannedBytes = new JsonlFileSink(root, indexName).estimateBytes(prepared)
                    + new BulkNdjsonFileSink(root, indexName).estimateBytes(prepared);
            long existingBytes = Files.size(existingJsonl);
            RuntimeConfig.updateState(fileExportState(root, true, existingBytes + plannedBytes - 1L, false, 95, true));
            AtomicReference<String> status = new AtomicReference<>();
            ControlStatusBridge.register(status::set);

            FileExportService.emit(prepared);

            assertThat(Files.readString(existingJsonl)).isEqualTo("{\"seed\":true}\n");
            assertThat(root.resolve(indexName + ".ndjson")).doesNotExist();
            assertThat(status.get()).contains("OpenSearch export continues.");
            assertThat(RuntimeConfig.isOpenSearchExportEnabled()).isTrue();
            assertThat(FileExportStats.getFailureCount("traffic")).isEqualTo(1L);
        });
    }

    @Test
    void createSelectedExportFiles_createsExpectedFilesWhenExporterSourceIsSelected() throws Exception {
        withCleanup(() -> {
            Path root = TestPathSupport.createDirectory("file-export-init");
            Path rootAbs = root.toAbsolutePath().normalize();
            RuntimeConfig.updateState(fileExportState(rootAbs, true, Long.MAX_VALUE, false, 95));

            List<FileExportService.FileInitResult> results =
                    FileExportService.createSelectedExportFiles(List.of("settings", "traffic", "exporter"));

            assertThat(results)
                    .extracting(FileExportService.FileInitResult::status)
                    .containsOnly(ai.attackframework.tools.burp.utils.FileUtil.Status.CREATED);
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("settings") + ".jsonl")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("settings") + ".ndjson")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("traffic") + ".jsonl")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("traffic") + ".ndjson")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl")).exists();
            assertThat(rootAbs.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson")).exists();
        });
    }

    private void withCleanup(ThrowingRunnable action) throws Exception {
        try {
            action.run();
        } finally {
            RuntimeConfig.updateState(previous);
            FileExportService.resetForTests();
            ControlStatusBridge.clear();
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static ConfigState.State fileExportState(Path root, boolean totalEnabled, long totalBytes,
                                                     boolean diskPercentEnabled, int diskPercent) {
        return fileExportState(root, totalEnabled, totalBytes, diskPercentEnabled, diskPercent, false);
    }

    private static ConfigState.State fileExportState(Path root, boolean totalEnabled, long totalBytes,
                                                     boolean diskPercentEnabled, int diskPercent,
                                                     boolean openSearchEnabled) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, root.toString(), true, true,
                        totalEnabled, ConfigState.bytesToGb(totalBytes),
                        diskPercentEnabled, diskPercent,
                        openSearchEnabled, openSearchEnabled ? "https://opensearch.url:9200" : "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }

    private static Map<String, Object> sampleDocument() {
        return sampleDocument("https://acme.com/api");
    }

    private static Map<String, Object> sampleDocument(String url) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-03-27T00:00:00Z");

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("url", url);
        request.put("method", "GET");

        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", burp);
        document.put("request", request);
        document.put("meta", meta);
        return document;
    }
}
