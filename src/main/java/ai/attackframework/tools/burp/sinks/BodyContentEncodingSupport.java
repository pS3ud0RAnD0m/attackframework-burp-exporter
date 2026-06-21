package ai.attackframework.tools.burp.sinks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.brotli.dec.BrotliInputStream;

import com.github.luben.zstd.ZstdInputStream;

import burp.api.montoya.http.message.HttpHeader;

/**
 * Resolves request/response body bytes for analysis when {@code Content-Encoding} compresses the wire
 * payload.
 *
 * <p>Wire bytes are always preserved for {@code body.b64}; logical bytes are decompressed when
 * recognized encodings are present so content-type inference, text extraction, and urlencoded BODY
 * parameter parsing can operate on the semantic payload.</p>
 *
 * <p>Supported tokens: {@code gzip}, {@code x-gzip}, {@code deflate}, {@code br}, {@code zstd},
 * {@code compress}, {@code x-compress}. {@code identity} is ignored.</p>
 */
final class BodyContentEncodingSupport {

    /** Maximum expanded bytes accepted from a single decompression step (zip-bomb guard). */
    static final int MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024;

    private static final CompressorStreamFactory COMPRESSOR_FACTORY = CompressorStreamFactory.getSingleton();

    private BodyContentEncodingSupport() {}

    /**
     * Wire body bytes plus a logical view used for sniffing, text export, and supplemental parsing.
     *
     * @param wireBytes original on-the-wire body bytes (never {@code null})
     * @param logicalBytes bytes used for inference and text parsing (decompressed when successful)
     * @param transformed whether {@code logicalBytes} differs from {@code wireBytes}
     * @param encodingsApplied Content-Encoding tokens applied, in decode order; empty when unchanged
     */
    record ResolvedBody(byte[] wireBytes, byte[] logicalBytes, boolean transformed, List<String> encodingsApplied) {

        static ResolvedBody unchanged(byte[] wireBytes) {
            byte[] safe = wireBytes == null ? new byte[0] : wireBytes;
            return new ResolvedBody(safe, safe, false, List.of());
        }
    }

    /**
     * Returns logical body bytes for analysis, decompressing when {@code Content-Encoding} indicates
     * a supported codec.
     *
     * @param wireBytes on-the-wire body; {@code null} treated as empty
     * @param headers message headers carrying {@code Content-Encoding}; may be {@code null}
     * @return resolved view; never {@code null}
     */
    static ResolvedBody resolve(byte[] wireBytes, List<HttpHeader> headers) {
        if (wireBytes == null || wireBytes.length == 0) {
            return ResolvedBody.unchanged(wireBytes);
        }
        List<String> encodings = contentEncodings(headers);
        if (encodings.isEmpty()) {
            return ResolvedBody.unchanged(wireBytes);
        }
        byte[] current = wireBytes;
        List<String> applied = new ArrayList<>();
        for (int i = encodings.size() - 1; i >= 0; i--) {
            String token = encodings.get(i);
            byte[] next = decompressToken(token, current);
            if (next == null) {
                break;
            }
            applied.add(token);
            current = next;
        }
        if (applied.isEmpty() || Arrays.equals(current, wireBytes)) {
            return ResolvedBody.unchanged(wireBytes);
        }
        return new ResolvedBody(wireBytes, current, true, List.copyOf(applied));
    }

    /**
     * Attempts a single-step gzip decompress when the wire body has gzip magic but no
     * {@code Content-Encoding} header.
     *
     * @param wireBytes on-the-wire body
     * @param declaredForm whether Content-Type indicates form or multipart
     * @return gzip resolution when magic matches and decompress succeeds; otherwise unchanged view
     */
    static ResolvedBody trySniffGzipForDeclaredForm(byte[] wireBytes, boolean declaredForm) {
        if (!declaredForm || wireBytes == null || wireBytes.length < 2) {
            return ResolvedBody.unchanged(wireBytes);
        }
        if ((wireBytes[0] != (byte) 0x1f) || (wireBytes[1] != (byte) 0x8b)) {
            return ResolvedBody.unchanged(wireBytes);
        }
        byte[] decompressed = decompressGzip(wireBytes);
        if (decompressed == null || Arrays.equals(decompressed, wireBytes)) {
            return ResolvedBody.unchanged(wireBytes);
        }
        return new ResolvedBody(wireBytes, decompressed, true, List.of("gzip"));
    }

    /**
     * Resolves logical bytes for export, applying Content-Encoding removal when the primary
     * media type and headers warrant decompression.
     *
     * <p>Decompresses when {@code Content-Encoding} is present and the primary media type is
     * eligible (text, form, multipart, or {@code application/octet-stream} with encoding). Skips
     * decompress for {@code image/*} and similar never-agent-text families even when compressed.
     * Request-only declared form/multipart gzip magic sniff runs when {@code allowDeclaredFormGzipSniff}
     * is true.</p>
     *
     * @param wireBytes on-the-wire body
     * @param headers message headers
     * @param primaryMediaType resolved primary Content-Type; may be {@code null}
     * @param declaredFormOrMultipart whether Content-Type indicates form or multipart
     * @param allowDeclaredFormGzipSniff whether request-only gzip magic sniff is allowed
     * @return resolved view; never {@code null}
     */
    static ResolvedBody resolveForExport(
            byte[] wireBytes,
            List<HttpHeader> headers,
            String primaryMediaType,
            boolean declaredFormOrMultipart,
            boolean allowDeclaredFormGzipSniff) {
        if (wireBytes == null || wireBytes.length == 0) {
            return ResolvedBody.unchanged(wireBytes);
        }
        if (allowDeclaredFormGzipSniff) {
            ResolvedBody sniffed = trySniffGzipForDeclaredForm(wireBytes, declaredFormOrMultipart);
            if (sniffed.transformed()) {
                return sniffed;
            }
        }
        if (contentEncodings(headers).isEmpty()) {
            return ResolvedBody.unchanged(wireBytes);
        }
        if (!shouldDecompressForContentEncoding(primaryMediaType)) {
            return ResolvedBody.unchanged(wireBytes);
        }
        return resolve(wireBytes, headers);
    }

    /**
     * Returns whether {@code Content-Encoding} decompression is applied for the given primary
     * media type.
     *
     * <p>Caller must ensure a {@code Content-Encoding} header is present before invoking.</p>
     *
     * @param primaryMediaType resolved primary Content-Type; may be {@code null}
     * @return {@code true} when logical bytes should be decompressed for export analysis
     */
    static boolean shouldDecompressForContentEncoding(String primaryMediaType) {
        if (primaryMediaType == null || primaryMediaType.isBlank()) {
            return false;
        }
        if (isNeverDecompressMediaFamily(primaryMediaType)) {
            return false;
        }
        if ("application/octet-stream".equals(primaryMediaType)) {
            return true;
        }
        if (primaryMediaType.startsWith("multipart/")) {
            return true;
        }
        return HttpMessageDocSupport.isTextualMediaType(primaryMediaType);
    }

    private static boolean isNeverDecompressMediaFamily(String mediaType) {
        return mediaType.startsWith("image/")
                || mediaType.startsWith("audio/")
                || mediaType.startsWith("video/")
                || mediaType.startsWith("font/")
                || mediaType.startsWith("model/");
    }

    /**
     * Returns normalized {@code Content-Encoding} tokens from {@code headers}, outermost last.
     *
     * <p>{@code identity} and blank tokens are omitted. Returns an empty list when the header is
     * absent.</p>
     *
     * @param headers message headers; may be {@code null}
     * @return ordered encoding tokens; never {@code null}
     */
    static List<String> contentEncodings(List<HttpHeader> headers) {
        String header = HttpMessageDocSupport.headerValue(headers, "Content-Encoding");
        if (header == null || header.isBlank()) {
            return List.of();
        }
        String[] parts = header.toLowerCase(Locale.ROOT).split(",");
        List<String> out = new ArrayList<>(parts.length);
        for (String part : parts) {
            String token = part.trim();
            if (token.isEmpty() || "identity".equals(token)) {
                continue;
            }
            out.add(token);
        }
        return out;
    }

    private static byte[] decompressToken(String token, byte[] input) {
        return switch (token) {
            case "gzip", "x-gzip" -> decompressGzip(input);
            case "deflate" -> decompressDeflate(input);
            case "br" -> decompressBrotli(input);
            case "zstd" -> decompressZstd(input);
            case "compress", "x-compress" -> decompressUnixCompress(input);
            default -> null;
        };
    }

    private static byte[] decompressGzip(byte[] input) {
        if (input == null || input.length < 2) {
            return null;
        }
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(input));
                ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(input.length * 4, 65_536))) {
            return readBounded(in, out);
        } catch (IOException ignored) {
            return null;
        }
    }

    private static byte[] decompressDeflate(byte[] input) {
        if (input == null || input.length == 0) {
            return null;
        }
        byte[] zlib = decompressInflater(input, false);
        if (zlib != null) {
            return zlib;
        }
        return decompressInflater(input, true);
    }

    private static byte[] decompressInflater(byte[] input, boolean nowrap) {
        try (InputStream in = new InflaterInputStream(new ByteArrayInputStream(input), new Inflater(nowrap));
                ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(input.length * 4, 65_536))) {
            return readBounded(in, out);
        } catch (IOException ignored) {
            return null;
        }
    }

    private static byte[] decompressBrotli(byte[] input) {
        if (input == null || input.length == 0) {
            return null;
        }
        try (InputStream in = new BrotliInputStream(new ByteArrayInputStream(input));
                ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(input.length * 4, 65_536))) {
            return readBounded(in, out);
        } catch (IOException ignored) {
            return null;
        }
    }

    private static byte[] decompressZstd(byte[] input) {
        if (input == null || input.length == 0) {
            return null;
        }
        try (InputStream in = new ZstdInputStream(new ByteArrayInputStream(input));
                ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(input.length * 4, 65_536))) {
            return readBounded(in, out);
        } catch (IOException ignored) {
            return null;
        }
    }

    private static byte[] decompressUnixCompress(byte[] input) {
        if (input == null || input.length == 0) {
            return null;
        }
        try (CompressorInputStream in =
                        COMPRESSOR_FACTORY.createCompressorInputStream(CompressorStreamFactory.Z, new ByteArrayInputStream(input));
                ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(input.length * 4, 65_536))) {
            return readBounded(in, out);
        } catch (IOException ignored) {
            return null;
        }
    }

    private static byte[] readBounded(InputStream in, ByteArrayOutputStream out) throws IOException {
        byte[] buffer = new byte[8_192];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) >= 0) {
            if (read == 0) {
                continue;
            }
            total += read;
            if (total > MAX_DECOMPRESSED_BYTES) {
                return null;
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
