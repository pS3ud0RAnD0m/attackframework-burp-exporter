package ai.attackframework.tools.burp.testutils;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Lightweight reflection helpers for tests.
 * Supports null arguments, primitive parameters, and overload resolution.
 *
 * <p>Test convention: prefer this helper over ad-hoc {@code getDeclared*}/{@code setAccessible}
 * usage in individual tests so reflection behavior stays consistent and maintainable.</p>
 */
public final class Reflect {

    private Reflect() {}

    /**
     * Returns the value of a (possibly private) field by name.
     *
     * @param target    instance declaring (or inheriting) the field
     * @param fieldName declared field name
     * @param <T>       expected type
     * @return field value cast to T
     */
    @SuppressWarnings("unchecked") // Caller is responsible for requesting the correct field type.
    public static <T> T get(Object target, String fieldName) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(fieldName, "fieldName");
        try {
            Field f = findField(target.getClass(), fieldName);
            makeAccessible(f, target);
            return (T) f.get(target);
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException("get(field=" + fieldName + ")", e);
        }
    }

    /**
     * Returns and casts the value of a (possibly private) field by name.
     *
     * @param target    instance declaring (or inheriting) the field
     * @param fieldName declared field name
     * @param type      expected field type
     * @param <T>       expected type
     * @return field value cast to {@code type}
     */
    public static <T> T get(Object target, String fieldName, Class<T> type) {
        Objects.requireNonNull(type, "type");
        return type.cast(get(target, fieldName));
    }

    /**
     * Returns the value of a static (possibly private) field by name.
     *
     * @param owner     class declaring (or inheriting) the field
     * @param fieldName declared field name
     * @param <T>       expected type
     * @return field value cast to T
     */
    @SuppressWarnings("unchecked") // Caller is responsible for requesting the correct field type.
    public static <T> T getStatic(Class<?> owner, String fieldName) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(fieldName, "fieldName");
        try {
            Field f = findField(owner, fieldName);
            makeAccessible(f, null);
            return (T) f.get(null);
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException("getStatic(field=" + owner.getName() + "#" + fieldName + ")", e);
        }
    }

    /**
     * Sets a (possibly private) field by name.
     *
     * @param target    instance declaring (or inheriting) the field
     * @param fieldName declared field name
     * @param value     new value
     */
    public static void set(Object target, String fieldName, Object value) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(fieldName, "fieldName");
        try {
            Field f = findField(target.getClass(), fieldName);
            makeAccessible(f, target);
            f.set(target, value);
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException("set(field=" + fieldName + ")", e);
        }
    }

    /**
     * Sets a static (possibly private) field by name.
     *
     * @param owner     class declaring (or inheriting) the field
     * @param fieldName declared field name
     * @param value     new value
     */
    public static void setStatic(Class<?> owner, String fieldName, Object value) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(fieldName, "fieldName");
        try {
            Field f = findField(owner, fieldName);
            makeAccessible(f, null);
            f.set(null, value);
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException("setStatic(field=" + owner.getName() + "#" + fieldName + ")", e);
        }
    }

    /**
     * Invokes a (possibly private) method by name. Resolves overloads by arity and assignability,
     * and supports null arguments and primitive parameters.
     *
     * @param target     instance declaring (or inheriting) the method
     * @param methodName declared method name
     * @param args       arguments to pass (may contain nulls)
     * @return return value (or null for void)
     */
    public static Object call(Object target, String methodName, Object... args) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(methodName, "methodName");
        try {
            Method m = resolveMethod(target.getClass(), methodName, args);
            makeAccessible(m, target);
            return m.invoke(target, args);
        } catch (InvocationTargetException ite) {
            // Surface the underlying exception for clearer test failures.
            throw new RuntimeException(
                    "call(method=" + methodName + ", args=" + Arrays.toString(args) + ")",
                    ite.getTargetException());
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException(
                    "call(method=" + methodName + ", args=" + Arrays.toString(args) + ")", e);
        }
    }

    /**
     * Invokes a static (possibly private) method by name.
     *
     * @param owner      class declaring (or inheriting) the method
     * @param methodName declared method name
     * @param args       arguments to pass (may contain nulls)
     * @return return value (or null for void)
     */
    public static Object callStatic(Class<?> owner, String methodName, Object... args) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(methodName, "methodName");
        try {
            Method m = resolveMethod(owner, methodName, args);
            makeAccessible(m, null);
            return m.invoke(null, args);
        } catch (InvocationTargetException ite) {
            throw new RuntimeException(
                    "callStatic(method=" + owner.getName() + "#" + methodName + ", args=" + Arrays.toString(args) + ")",
                    ite.getTargetException());
        } catch (ReflectiveOperationException | SecurityException e) {
            throw new RuntimeException(
                    "callStatic(method=" + owner.getName() + "#" + methodName + ", args=" + Arrays.toString(args) + ")",
                    e);
        }
    }

    // ---------- internals ----------

    /**
     * Ensures the given reflective object is accessible for the provided receiver.
     * Uses a non-null receiver for instance members (Java 9+ {@code canAccess} requirement),
     * and {@code null} for static members.
     */
    private static void makeAccessible(AccessibleObject ao, Object receiver) {
        Objects.requireNonNull(ao, "ao");
        try {
            if (ao instanceof Field f) {
                boolean isStatic = Modifier.isStatic(f.getModifiers());
                Object rec = isStatic ? null : receiver;
                if (!f.canAccess(rec)) f.setAccessible(true);
                return;
            }
            if (ao instanceof Method m) {
                boolean isStatic = Modifier.isStatic(m.getModifiers());
                Object rec = isStatic ? null : receiver;
                if (!m.canAccess(rec)) m.setAccessible(true);
                return;
            }
            // Fallback for other AccessibleObject types.
            if (receiver == null) {
                ao.setAccessible(true);
            } else if (!ao.canAccess(receiver)) {
                ao.setAccessible(true);
            }
        } catch (IllegalArgumentException ignored) {
            // Some JDKs throw when receiver is null for instance members; force accessibility.
            ao.setAccessible(true);
        } catch (SecurityException se) {
            throw new RuntimeException("makeAccessible failed for " + ao, se);
        }
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(name, "name");
        for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                // Continue up the inheritance hierarchy.
            }
        }
        throw new NoSuchFieldException(type.getName() + "#" + name);
    }

    private static Method resolveMethod(Class<?> type, String name, Object[] args) throws NoSuchMethodException {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(name, "name");
        List<Method> candidates = findMethods(type, name);
        for (Method m : candidates) {
            if (arityMatches(m, args) && argsMatch(m.getParameterTypes(), args)) {
                return m;
            }
        }
        int arity = (args == null) ? 0 : args.length;
        throw new NoSuchMethodException(type.getName() + "#" + name + "(" + arity + ")");
    }

    private static List<Method> findMethods(Class<?> type, String name) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(name, "name");
        List<Method> all = new ArrayList<>();
        Class<?> c = type;
        while (c != null && c != Object.class) {
            for (Method m : c.getDeclaredMethods()) {
                if (name.equals(m.getName())) {
                    all.add(m);
                }
            }
            c = c.getSuperclass();
        }
        return all;
    }

    private static boolean arityMatches(Method m, Object[] args) {
        int n = (args == null) ? 0 : args.length;
        return m.getParameterCount() == n;
    }

    /**
     * Verifies that each argument is assignable to the corresponding parameter type,
     * accounting for nulls and primitive vs. wrapper types.
     */
    private static boolean argsMatch(Class<?>[] paramTypes, Object[] args) {
        if (paramTypes.length == 0) return args == null || args.length == 0;
        for (int i = 0; i < paramTypes.length; i++) {
            Class<?> p = paramTypes[i];
            Object a = args[i];
            if (a == null) {
                if (p.isPrimitive()) return false; // cannot assign null to a primitive parameter
                continue;
            }
            Class<?> aWrapped = wrap(a.getClass());
            Class<?> pWrapped = wrap(p);
            if (!pWrapped.isAssignableFrom(aWrapped)) return false;
        }
        return true;
    }

    private static Class<?> wrap(Class<?> c) {
        if (!c.isPrimitive()) return c;
        if (c == boolean.class) return Boolean.class;
        if (c == byte.class)    return Byte.class;
        if (c == short.class)   return Short.class;
        if (c == char.class)    return Character.class;
        if (c == int.class)     return Integer.class;
        if (c == long.class)    return Long.class;
        if (c == float.class)   return Float.class;
        if (c == double.class)  return Double.class;
        return c;
    }
}
