package ai.attackframework.tools.burp.testutils;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Objects;

import burp.api.montoya.MontoyaApi;

/**
 * Builds a minimal dynamic-proxy Montoya API suitable for secure-store tests.
 *
 * <p>The proxy implements {@code persistence().extensionData()/preferences()} and
 * their {@code getString/setString/deleteString} methods backed by the provided map.</p>
 */
public final class SecureStoreMontoyaMock {

    private SecureStoreMontoyaMock() {}

    public static MontoyaApi create(Map<String, String> backing) {
        Objects.requireNonNull(backing, "backing");
        Class<?> persistenceType = methodReturnType(MontoyaApi.class, "persistence");
        Class<?> extensionType = methodReturnType(persistenceType, "extensionData");
        Class<?> preferencesType = methodReturnType(persistenceType, "preferences");

        Object extensionStore = storeProxy(extensionType, backing);
        Object preferencesStore = storeProxy(preferencesType, backing);
        Object persistence = Proxy.newProxyInstance(
                persistenceType.getClassLoader(),
                new Class<?>[] { persistenceType },
                (proxy, method, args) -> switch (method.getName()) {
                    case "extensionData" -> extensionStore;
                    case "preferences" -> preferencesStore;
                    default -> defaultValue(method.getReturnType());
                });

        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(),
                new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> {
                    if ("persistence".equals(method.getName())) {
                        return persistence;
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Object storeProxy(Class<?> storeType, Map<String, String> backing) {
        InvocationHandler handler = (proxy, method, args) -> {
            String name = method.getName();
            if ("setString".equals(name) && args != null && args.length == 2) {
                backing.put(String.valueOf(args[0]), String.valueOf(args[1]));
                return null;
            }
            if ("getString".equals(name) && args != null && args.length == 1) {
                return backing.getOrDefault(String.valueOf(args[0]), "");
            }
            if ("deleteString".equals(name) && args != null && args.length == 1) {
                backing.remove(String.valueOf(args[0]));
                return null;
            }
            return defaultValue(method.getReturnType());
        };
        return Proxy.newProxyInstance(storeType.getClassLoader(), new Class<?>[] { storeType }, handler);
    }

    private static Class<?> methodReturnType(Class<?> owner, String methodName) {
        try {
            Method m = owner.getMethod(methodName);
            return m.getReturnType();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Missing method " + owner.getName() + "#" + methodName, e);
        }
    }

    private static Object defaultValue(Class<?> returnType) {
        if (!returnType.isPrimitive()) {
            if (returnType.isEnum()) {
                Object[] constants = returnType.getEnumConstants();
                return constants != null && constants.length > 0 ? constants[0] : null;
            }
            if (returnType.isInterface()) {
                return Proxy.newProxyInstance(
                        returnType.getClassLoader(),
                        new Class<?>[] { returnType },
                        (proxy, method, args) -> {
                            if (method.getDeclaringClass() == Object.class) {
                                if ("toString".equals(method.getName())) {
                                    return "SecureStoreMontoyaMock[" + returnType.getSimpleName() + "]";
                                }
                                if ("hashCode".equals(method.getName())) {
                                    return System.identityHashCode(proxy);
                                }
                                if ("equals".equals(method.getName())) {
                                    return proxy == (args == null ? null : args[0]);
                                }
                            }
                            return defaultValue(method.getReturnType());
                        });
            }
            return null;
        }
        if (returnType == boolean.class) return false;
        if (returnType == byte.class) return (byte) 0;
        if (returnType == short.class) return (short) 0;
        if (returnType == int.class) return 0;
        if (returnType == long.class) return 0L;
        if (returnType == float.class) return 0f;
        if (returnType == double.class) return 0d;
        if (returnType == char.class) return '\0';
        return null;
    }
}
