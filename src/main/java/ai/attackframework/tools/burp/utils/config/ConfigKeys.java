package ai.attackframework.tools.burp.utils.config;

/**
 * Shared string keys for sources and scope types used across UI and config mapping.
 *
 * <p>Centralizing avoids drift in literals between UI, mapper, and tests.</p>
 */
public final class ConfigKeys {
    private ConfigKeys() {}

    // Source keys
    public static final String SRC_SETTINGS = "settings";
    public static final String SRC_SITEMAP  = "sitemap";
    public static final String SRC_FINDINGS = "findings";
    public static final String SRC_TRAFFIC  = "traffic";
    public static final String SRC_EXPORTER = "exporter";

    // Scope types
    public static final String SCOPE_ALL    = "all";
    public static final String SCOPE_BURP   = "burp";
    public static final String SCOPE_CUSTOM = "custom";

    // Settings sub-options
    public static final String SRC_SETTINGS_PROJECT = "project";
    public static final String SRC_SETTINGS_USER    = "user";

    // Exporter sub-options
    public static final String SRC_EXPORTER_TRACE  = "trace";
    public static final String SRC_EXPORTER_DEBUG  = "debug";
    public static final String SRC_EXPORTER_INFO   = "info";
    public static final String SRC_EXPORTER_WARN   = "warn";
    public static final String SRC_EXPORTER_ERROR  = "error";
    public static final String SRC_EXPORTER_STATS  = "stats";
    public static final String SRC_EXPORTER_CONFIG = "config";
}
