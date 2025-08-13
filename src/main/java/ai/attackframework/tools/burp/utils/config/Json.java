package ai.attackframework.tools.burp.utils.config;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal JSON helpers for exporting/importing the ConfigPanel state.
 * Intentionally lightweight (no external JSON libs) and tailored to the panel’s format.
 */
public final class Json {

    private Json() {}

    /** Container representing the parsed config snapshot. */
    public static final class ImportedConfig {
        public final List<String> dataSources = new ArrayList<>();
        public String scopeType = "all";              // "custom" | "burp" | "all"
        public final List<String> scopeRegexes = new ArrayList<>();
        public String filesPath;                      // nullable
        public String openSearchUrl;                  // nullable
    }

    /** Builds a pretty-printed JSON snapshot of current config (non-secret settings only). */
    public static String buildPrettyConfigJson(
            List<String> sources,
            String scopeType,               // "burp" | "custom" | "all"
            List<String> scopeRegexes,      // only when custom; may be empty
            boolean filesEnabled,
            String filesRoot,
            boolean openSearchEnabled,
            String openSearchUrl) {

        String indent = "  ";
        String indent2 = indent + indent;
        String indent3 = indent2 + indent;

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        sb.append(indent).append("\"dataSources\": [");
        if (sources != null && !sources.isEmpty()) {
            sb.append("\n");
            for (int i = 0; i < sources.size(); i++) {
                sb.append(indent2).append("\"").append(jsonEscape(sources.get(i))).append("\"");
                if (i < sources.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append(indent).append("],\n");
        } else {
            sb.append("],\n");
        }

        // scope object (tight form): { "custom": [ ... ] } OR { "burp": [] } OR { "all": [] }
        sb.append(indent).append("\"scope\": {\n");
        if ("custom".equals(scopeType)) {
            sb.append(indent2).append("\"custom\": [");
            if (scopeRegexes != null && !scopeRegexes.isEmpty()) {
                sb.append("\n");
                for (int i = 0; i < scopeRegexes.size(); i++) {
                    sb.append(indent3).append("\"").append(jsonEscape(scopeRegexes.get(i))).append("\"");
                    if (i < scopeRegexes.size() - 1) sb.append(",");
                    sb.append("\n");
                }
                sb.append(indent2).append("]\n");
            } else {
                sb.append("]\n");
            }
        } else if ("burp".equals(scopeType)) {
            sb.append(indent2).append("\"burp\": []\n");
        } else {
            sb.append(indent2).append("\"all\": []\n");
        }
        sb.append(indent).append("},\n");

        // sinks — only include selected sinks; values are direct strings (path or URL)
        sb.append(indent).append("\"sinks\": {\n");
        List<String> sinkLines = new ArrayList<>();
        if (filesEnabled) {
            sinkLines.add(indent2 + "\"files\": \"" + jsonEscape(filesRoot != null ? filesRoot : "") + "\"");
        }
        if (openSearchEnabled) {
            sinkLines.add(indent2 + "\"openSearch\": \"" + jsonEscape(openSearchUrl != null ? openSearchUrl : "") + "\"");
        }
        if (!sinkLines.isEmpty()) {
            for (int i = 0; i < sinkLines.size(); i++) {
                sb.append(sinkLines.get(i));
                if (i < sinkLines.size() - 1) sb.append(",\n");
            }
            sb.append("\n").append(indent).append("}\n");
        } else {
            sb.append(indent).append("}\n");
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Parses the JSON produced by {@link #buildPrettyConfigJson}.
     * Minimal/tolerant regex-based parser; not intended for general JSON.
     */
    public static ImportedConfig parseConfigJson(String json) {
        ImportedConfig cfg = new ImportedConfig();
        String src = json == null ? "" : json;

        // dataSources: extract ["...","..."]
        Matcher mDs = Pattern.compile("\"dataSources\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(src);
        if (mDs.find()) {
            String arr = mDs.group(1);
            Matcher mVals = Pattern.compile("\"(.*?)\"", Pattern.DOTALL).matcher(arr);
            while (mVals.find()) cfg.dataSources.add(jsonUnescape(mVals.group(1)));
        }

        // scope: { ... } then check which key exists
        Matcher mScope = Pattern.compile("\"scope\"\\s*:\\s*\\{(.*?)}", Pattern.DOTALL).matcher(src);
        if (mScope.find()) {
            String inner = mScope.group(1);
            if (inner.contains("\"custom\"")) {
                cfg.scopeType = "custom";
                Matcher mCustomArr = Pattern.compile("\"custom\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(inner);
                if (mCustomArr.find()) {
                    String arr = mCustomArr.group(1);
                    Matcher mVals = Pattern.compile("\"(.*?)\"", Pattern.DOTALL).matcher(arr);
                    while (mVals.find()) cfg.scopeRegexes.add(jsonUnescape(mVals.group(1)));
                }
            } else if (inner.contains("\"burp\"")) {
                cfg.scopeType = "burp";
            } else {
                cfg.scopeType = "all";
            }
        }

        // sinks: look for "files":"..." and/or "openSearch":"..."
        Matcher mFiles = Pattern.compile("\"files\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(src);
        if (mFiles.find()) cfg.filesPath = jsonUnescape(mFiles.group(1));

        Matcher mOs = Pattern.compile("\"openSearch\"\\s*:\\s*\"(.*?)\"", Pattern.DOTALL).matcher(src);
        if (mOs.find()) cfg.openSearchUrl = jsonUnescape(mOs.group(1));

        return cfg;
    }

    // ---- minimal escaping helpers ----

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }

    private static String jsonUnescape(String s) {
        if (s == null || s.indexOf('\\') < 0) return s;
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case '\"': out.append('\"'); break;
                    case '\\': out.append('\\'); break;
                    case '/':  out.append('/');  break;
                    case 'b':  out.append('\b'); break;
                    case 'f':  out.append('\f'); break;
                    case 'n':  out.append('\n'); break;
                    case 'r':  out.append('\r'); break;
                    case 't':  out.append('\t'); break;
                    case 'u':
                        if (i + 4 < s.length()) {
                            String hex = s.substring(i + 1, i + 5);
                            try { out.append((char) Integer.parseInt(hex, 16)); i += 4; }
                            catch (NumberFormatException nfe) { out.append("\\u").append(hex); i += 4; }
                        } else {
                            out.append("\\u");
                        }
                        break;
                    default: out.append(n);
                }
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
