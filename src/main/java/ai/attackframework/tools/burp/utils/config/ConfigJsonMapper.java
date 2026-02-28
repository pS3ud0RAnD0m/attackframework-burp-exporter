package ai.attackframework.tools.burp.utils.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ai.attackframework.tools.burp.utils.config.ConfigState.ScopeEntry;
import ai.attackframework.tools.burp.utils.config.ConfigState.Sinks;
import ai.attackframework.tools.burp.utils.config.ConfigState.State;

/**
 * Mapper between the typed {@link ConfigState.State} and the JSON produced/parsed
 * by {@link Json}. Keeps JSON shape 100% compatible by delegating to {@link Json}.
 */
public final class ConfigJsonMapper {

    private ConfigJsonMapper() { }

    /** Build JSON from a typed state using {@link Json} under the hood. */
    public static String build(State state) {
        return Json.buildFromState(state);
    }

    /** Parse JSON into a typed state via {@link Json#parseConfigJson(String)}. */
    public static State parse(String json) throws IOException {
        Json.ImportedConfig cfg = Json.parseConfigJson(json);
        List<ScopeEntry> entries = entriesFrom(cfg);

        Sinks sinks = new Sinks(
                cfg.filesPath() != null && !cfg.filesPath().isBlank(), cfg.filesPath(),
                cfg.openSearchUrl() != null && !cfg.openSearchUrl().isBlank(), cfg.openSearchUrl()
        );

        return new State(cfg.dataSources(), cfg.scopeType(), entries, sinks,
                cfg.settingsSub(), cfg.trafficToolTypes(), cfg.findingsSeverities());
    }

    /** Extract ordered custom entries from the parsed config. */
    private static List<ScopeEntry> entriesFrom(Json.ImportedConfig cfg) {
        List<ScopeEntry> out = new ArrayList<>();
        if (!"custom".equals(cfg.scopeType())) return out;

        List<String> vals  = cfg.scopeRegexes();
        List<String> kinds = cfg.scopeKinds(); // may be null
        int n = (vals == null) ? 0 : vals.size();

        boolean typed = kinds != null && kinds.size() == n;
        for (int i = 0; i < n; i++) {
            String v = vals.get(i);
            String k = typed ? kinds.get(i) : "regex";
            out.add(new ScopeEntry(v, "string".equalsIgnoreCase(k)
                    ? ConfigState.Kind.STRING
                    : ConfigState.Kind.REGEX));
        }
        return out;
    }
}
