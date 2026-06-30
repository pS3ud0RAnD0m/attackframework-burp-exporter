package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import burp.api.montoya.http.message.HttpHeader;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link BodyContentEncodingSupport}. */
class BodyContentEncodingSupportTest {

    @Test
    void resolve_gzipContentEncoding_decompressesLogicalBytes() throws Exception {
        byte[] plain = "org_id=abc&ja=123".getBytes(StandardCharsets.UTF_8);
        byte[] gzip = gzip(plain);
        HttpHeader encoding = header("Content-Encoding", "gzip");
        HttpHeader contentType = header("Content-Type", "application/x-www-form-urlencoded");

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolve(gzip, List.of(encoding, contentType));

        assertThat(resolved.transformed()).isTrue();
        assertThat(resolved.encodingsApplied()).containsExactly("gzip");
        assertThat(resolved.logicalBytes()).isEqualTo(plain);
        assertThat(resolved.wireBytes()).isEqualTo(gzip);
    }

    @Test
    void resolveForExport_declaredFormGzipMagicWithoutHeader_sniffsGzip() throws Exception {
        byte[] plain = "a=1&b=2".getBytes(StandardCharsets.UTF_8);
        byte[] gzip = gzip(plain);

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolveForExport(gzip, List.of(), null, true, true);

        assertThat(resolved.transformed()).isTrue();
        assertThat(resolved.logicalBytes()).isEqualTo(plain);
    }

    @Test
    void resolveForExport_declaredFormGzipMagicWithoutHeader_skippedWhenNotDeclaredForm() throws Exception {
        byte[] plain = "a=1&b=2".getBytes(StandardCharsets.UTF_8);
        byte[] gzip = gzip(plain);

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolveForExport(gzip, List.of(), null, false, true);

        assertThat(resolved.transformed()).isFalse();
        assertThat(resolved.logicalBytes()).isEqualTo(gzip);
    }

    @Test
    void resolve_oversizedOutput_returnsUnchanged() throws Exception {
        byte[] oversized = gzip(new byte[BodyContentEncodingSupport.MAX_DECOMPRESSED_BYTES + 1]);
        HttpHeader encoding = header("Content-Encoding", "gzip");

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolve(oversized, List.of(encoding));

        assertThat(resolved.transformed()).isFalse();
        assertThat(resolved.logicalBytes()).isEqualTo(oversized);
    }

    @Test
    void resolve_brotliContentEncoding_decompressesLogicalBytes() throws Exception {
        byte[] plain = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
        byte[] brotli = brotliCompress(plain);
        HttpHeader encoding = header("Content-Encoding", "br");

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolve(brotli, List.of(encoding));

        assertThat(resolved.transformed()).isTrue();
        assertThat(resolved.encodingsApplied()).containsExactly("br");
        assertThat(resolved.logicalBytes()).isEqualTo(plain);
    }

    @Test
    void resolve_zstdContentEncoding_decompressesLogicalBytes() throws Exception {
        byte[] plain = "payload=zstd".getBytes(StandardCharsets.UTF_8);
        byte[] zstd = com.github.luben.zstd.Zstd.compress(plain);
        HttpHeader encoding = header("Content-Encoding", "zstd");

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolve(zstd, List.of(encoding));

        assertThat(resolved.transformed()).isTrue();
        assertThat(resolved.encodingsApplied()).containsExactly("zstd");
        assertThat(resolved.logicalBytes()).isEqualTo(plain);
    }

    @Test
    void resolve_unsupportedEncoding_returnsUnchanged() {
        byte[] wire = "raw".getBytes(StandardCharsets.UTF_8);
        HttpHeader encoding = header("Content-Encoding", "unknown-custom");

        BodyContentEncodingSupport.ResolvedBody resolved =
                BodyContentEncodingSupport.resolve(wire, List.of(encoding));

        assertThat(resolved.transformed()).isFalse();
        assertThat(resolved.logicalBytes()).isEqualTo(wire);
    }

    private static byte[] brotliCompress(byte[] input) throws Exception {
        com.aayushatharva.brotli4j.Brotli4jLoader.ensureAvailability();
        return com.aayushatharva.brotli4j.encoder.Encoder.compress(input);
    }

    private static byte[] gzip(byte[] input) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(input);
        }
        return out.toByteArray();
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        org.mockito.Mockito.when(h.name()).thenReturn(name);
        org.mockito.Mockito.when(h.value()).thenReturn(value);
        return h;
    }
}
