package ai.attackframework.tools.burp.sinks;

import static ai.attackframework.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.attackframework.tools.burp.utils.MontoyaApiProvider;
import burp.api.montoya.MontoyaApi;

class ExporterIndexReporterStartupNullSafetyTest {

    @AfterEach
    void clearApiProvider() {
        MontoyaApiProvider.set(null);
    }

    @Test
    void exporterIndexHelpers_returnNull_whenBurpSubApisThrowDuringStartup() {
        MontoyaApiProvider.set(throwingMontoyaApi());

        assertThat(callStatic(ExporterIndexLogForwarder.class, "burpVersion")).isNull();
        assertThat(callStatic(ExporterIndexLogForwarder.class, "projectId")).isNull();

        assertThat(callStatic(ExporterIndexStatsReporter.class, "burpVersion")).isNull();
        assertThat(callStatic(ExporterIndexStatsReporter.class, "projectId")).isNull();

        assertThat(callStatic(ExporterIndexConfigReporter.class, "burpVersion")).isNull();
        assertThat(callStatic(ExporterIndexConfigReporter.class, "projectId")).isNull();
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

        boolean inScope = (boolean) callStatic(ProxyWebSocketIndexReporter.class, "safeBurpInScope", api, "https://example.com");
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
