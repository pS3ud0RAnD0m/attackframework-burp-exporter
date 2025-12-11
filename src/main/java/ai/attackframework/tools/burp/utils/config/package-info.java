/**
 * Utilities for serializing and deserializing the extension's configuration.
 *
 * <p>Includes JSON mapping helpers ({@link ai.attackframework.tools.burp.utils.config.ConfigJsonMapper}),
 * config key constants, and state holders. These classes are pure data/IO helpers with no Swing
 * dependencies and are safe to use from background threads. Filesystem concerns remain in
 * {@link ai.attackframework.tools.burp.utils.FileUtil} to keep boundaries clear.</p>
 */
package ai.attackframework.tools.burp.utils.config;
