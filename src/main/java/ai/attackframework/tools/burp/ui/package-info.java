/**
 * Swing UI for the Burp extension and the action controller.
 *
 * <p>The {@link ai.attackframework.tools.burp.ui.ConfigPanel} contains layout and lightweight
 * event wiring only; long-running actions are delegated to {@link ai.attackframework.tools.burp.ui.ConfigController},
 * which coordinates background work and reports results through a small {@link
 * ai.attackframework.tools.burp.ui.ConfigController.Ui} surface. The controller never touches Swing
 * components directly; it communicates via status strings and typed state objects.</p>
 *
 * <p>This separation keeps the UI responsive, simplifies testing, and avoids leaking business logic
 * into Swing listeners.</p>
 */
package ai.attackframework.tools.burp.ui;
