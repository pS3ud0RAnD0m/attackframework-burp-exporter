package ai.attackframework.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

class ConfigImportReportTest {

    @Test
    void formatControlStatusSummary_empty_returnsSimplePathMessage() {
        ConfigImportReport report = new ConfigImportReport();
        String status = report.formatControlStatusSummary(Path.of("C:\\cfg.json"));
        assertThat(status).isEqualTo("Imported configuration from: C:\\cfg.json");
    }

    @Test
    void formatControlStatusSummary_withWarnings_listsSkippedValuesAndAppliedNote() {
        ConfigImportReport report = new ConfigImportReport();
        report.add(ConfigImportReport.Kind.UNKNOWN_VALUE, "dataSources", "legacy");
        report.add(ConfigImportReport.Kind.UNKNOWN_VALUE, "exportFields.traffic", "request.body.removed");

        String status = report.formatControlStatusSummary(Path.of("cfg.json"));

        assertThat(status)
                .contains("Imported configuration from: cfg.json")
                .contains("2 setting(s) were not recognized and were skipped")
                .contains("Skipped:")
                .contains("dataSources \"legacy\"")
                .contains("exportFields.traffic \"request.body.removed\"")
                .contains("All other settings were applied");
    }

    @Test
    void formatLogLines_capsOutputAndNotesRemaining() {
        ConfigImportReport report = new ConfigImportReport();
        for (int i = 0; i < 25; i++) {
            report.add(ConfigImportReport.Kind.UNKNOWN_KEY, "exportFields.traffic", "field" + i);
        }

        var lines = report.formatLogLines(3);

        assertThat(lines.getFirst()).contains("25 value(s) were not recognized");
        assertThat(lines).anyMatch(line -> line.contains("… and 22 more"));
        assertThat(lines.getLast()).contains("All other settings from the file were applied");
    }
}
