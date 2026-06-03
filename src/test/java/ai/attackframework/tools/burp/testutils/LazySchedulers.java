package ai.attackframework.tools.burp.testutils;

import ai.attackframework.tools.burp.utils.concurrent.LazyScheduler;

import java.util.concurrent.ScheduledExecutorService;

/**
 * Test-only reflection helpers for {@link LazyScheduler}-backed owner classes.
 *
 * <p>Centralizes the "read the owner's static {@code LazyScheduler} field and call
 * {@link LazyScheduler#peek()}" idiom shared by every lifecycle/unload test so the underlying
 * reflection pattern stays in one place. Prefer this helper over ad-hoc {@code Reflect.getStatic}
 * plus {@code .peek()} chains in individual test classes.</p>
 */
public final class LazySchedulers {

    private LazySchedulers() {}

    /**
     * Returns the backing scheduler of an owner's static {@link LazyScheduler} field, or
     * {@code null} when the holder has not been started (or has been stopped).
     *
     * @param owner     class declaring the static {@link LazyScheduler} field
     * @param fieldName declared field name (for example {@code "SCHEDULER"} or
     *                  {@code "ORPHAN_SCHEDULER"})
     * @return the current {@link ScheduledExecutorService} inside the holder, or {@code null}
     */
    public static ScheduledExecutorService peek(Class<?> owner, String fieldName) {
        LazyScheduler holder = Reflect.getStatic(owner, fieldName, LazyScheduler.class);
        return holder == null ? null : holder.peek();
    }
}
