/**
 * Swing UI for the Burp extension.
 *
 * <p>The {@link ai.attackframework.tools.burp.ui.AttackFrameworkPanel} is the top-level tab
 * added to Burp. It embeds dedicated subpanels for configuration
 * ({@link ai.attackframework.tools.burp.ui.ConfigPanel}), logging
 * ({@link ai.attackframework.tools.burp.ui.LogPanel}), statistics, and the about box.</p>
 *
 * <p>{@link ai.attackframework.tools.burp.ui.ConfigPanel} owns all Swing components that
 * represent configuration state. It delegates long-running work to
 * {@link ai.attackframework.tools.burp.ui.controller.ConfigController}, which coordinates
 * background tasks and reports results through the
 * {@link ai.attackframework.tools.burp.ui.controller.ConfigController.Ui} callback surface.
 * The controller never touches Swing components directly; it communicates via status strings
 * and typed state objects.</p>
 *
 * <p>All UI construction and mutation occur on the EDT; background work is delegated to
 * controllers or utilities to keep panels responsive.</p>
 */
package ai.attackframework.tools.burp.ui;
