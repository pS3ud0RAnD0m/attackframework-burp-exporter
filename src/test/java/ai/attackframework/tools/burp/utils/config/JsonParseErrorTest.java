package ai.attackframework.tools.burp.utils.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies error surfacing: invalid JSON should propagate an IOException.
 */
class JsonParseErrorTest {

    @Test
    void parse_invalid_json_throwsIOException() {
        String invalid = "{";
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class);
    }

    @Test
    void parse_flat_sinks_shape_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "filesEnabled": true,
                "files": "/tmp/exports"
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.files")
                .hasMessageContaining("sinks.openSearch");
    }

    @Test
    void parse_unknown_sinks_field_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "files": {
                  "enabled": true
                },
                "openSearch": {
                  "enabled": true
                },
                "unexpected": {}
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.unexpected")
                .hasMessageContaining("Allowed fields: files, openSearch");
    }

    @Test
    void parse_unknown_files_format_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "files": {
                  "formats": [ "ndjson" ]
                }
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.files.formats[0]")
                .hasMessageContaining("Allowed values: jsonl, bulkNdjson");
    }

    @Test
    void parse_nonObject_nested_sink_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "files": ""
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.files")
                .hasMessageContaining("must be an object");
    }

    @Test
    void parse_unknown_files_limits_field_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "files": {
                  "limits": {
                    "totalEnabled": true,
                    "maxDiskPercent": 90
                  }
                }
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.files.limits.maxDiskPercent")
                .hasMessageContaining("Allowed fields: totalEnabled, totalGb, diskUsedPercentEnabled, maxDiskUsedPercent");
    }

    @Test
    void parse_unknown_openSearch_auth_field_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "openSearch": {
                  "auth": {
                    "type": "Basic",
                    "username": "admin",
                    "password": "secret"
                  }
                }
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.openSearch.auth.password")
                .hasMessageContaining("Allowed fields: type, username, apiKeyId, certPath, certKeyPath");
    }

    @Test
    void parse_basic_auth_with_apiKeyId_throwsIOException() {
        assertInvalidAuthFieldCombination("Basic", "apiKeyId", "kid-1");
    }

    @Test
    void parse_certificate_auth_with_username_throwsIOException() {
        assertInvalidAuthFieldCombination("Certificate", "username", "ops-user");
    }

    @Test
    void parse_none_auth_with_certPath_throwsIOException() {
        assertInvalidAuthFieldCombination("None", "certPath", "client.pem");
    }

    @Test
    void parse_unknown_pinned_certificate_field_throwsIOException() {
        String invalid = """
            {
              "sinks": {
                "openSearch": {
                  "pinnedTlsCertificate": {
                    "sourcePath": "cert.pem",
                    "sha256": "abc123"
                  }
                }
              }
            }
            """;
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.openSearch.pinnedTlsCertificate.sha256")
                .hasMessageContaining("Allowed fields: sourcePath, fingerprintSha256, encodedBase64");
    }

    private static void assertInvalidAuthFieldCombination(String authType, String fieldName, String fieldValue) {
        String invalid = """
            {
              "sinks": {
                "openSearch": {
                  "auth": {
                    "type": "%s",
                    "%s": "%s"
                  }
                }
              }
            }
            """.formatted(authType, fieldName, fieldValue);
        assertThatThrownBy(() -> Json.parseConfigJson(invalid))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("sinks.openSearch.auth." + fieldName)
                .hasMessageContaining("sinks.openSearch.auth.type")
                .hasMessageContaining(authType);
    }
}
