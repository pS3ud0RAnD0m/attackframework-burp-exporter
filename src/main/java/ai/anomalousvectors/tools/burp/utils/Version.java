package ai.anomalousvectors.tools.burp.utils;

/**
 * Centralized version accessor.
 *
 * Production: reads Implementation-Version from the JAR manifest.
 * Tests: may set {@code -Dburp.exporter.version=1.2.3} to run without a JAR.
 */
public final class Version {
    private Version() {}

    public static String get() {
        String override = System.getProperty("burp.exporter.version");
        if (override != null && !override.isBlank()) {
            return override.trim();
        }
        Package p = Version.class.getPackage();
        String mv = (p != null) ? p.getImplementationVersion() : null;
        if (mv == null || mv.isBlank()) {
            throw new IllegalStateException(
                    "Implementation-Version not found in manifest. " +
                            "Set -Dburp.exporter.version for tests or run from the packaged JAR."
            );
        }
        return mv;
    }
}
