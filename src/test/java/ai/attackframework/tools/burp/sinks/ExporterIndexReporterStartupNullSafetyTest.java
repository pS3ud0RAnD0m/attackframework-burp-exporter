package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.BurpRuntimeMetadata;
import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import burp.api.montoya.MontoyaApi;

class ExporterIndexReporterStartupNullSafetyTest {

    @AfterEach
    void clearApiProvider() {
        MontoyaApiProvider.set(null);
    }

    @Test
    void settingsBurpContextHelpers_fallBackSafely_whenBurpSubApisThrowDuringStartup() {
        MontoyaApi api = throwingMontoyaApi();
        MontoyaApiProvider.set(api);

        assertThat(callStatic(SettingsIndexReporter.class, "safeBurpVersion", api)).isNull();
        assertThat(callStatic(SettingsIndexReporter.class, "safeProjectId", api))
                .isEqualTo(BurpRuntimeMetadata.UNKNOWN_PROJECT_ID);
        clearApiProvider();
    }

    @Test
    void sitemapAndWebsocketHelpers_noop_whenMontoyaSubApisThrowDuringStartup() {
        MontoyaApi api = throwingMontoyaApi();

        assertThat(callStatic(SitemapIndexReporter.class, "safeSiteMapItems", api)).isNull();

        Object wsHistoryObj = callStatic(ProxyWebSocketIndexReporter.class, "safeWebSocketHistory", api);
        assertThat(wsHistoryObj).isInstanceOf(List.class);
        List<?> wsHistory = (List<?>) wsHistoryObj;
        assertThat(wsHistory).isEmpty();

        boolean inScope = WebSocketTrafficDocumentBuilder.safeBurpInScope(api, "https://example.com");
        assertThat(inScope).isFalse();
        clearApiProvider();
    }

    private static MontoyaApi throwingMontoyaApi() {
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(),
                new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> {
                    throw new NullPointerException("startup race: " + method.getName());
                });
    }
}
