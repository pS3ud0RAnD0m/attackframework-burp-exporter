package ai.attackframework.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PeriodicExportSeenKeysTest {

    @Test
    void isNew_returnsTrueUntilRecorded() {
        PeriodicExportSeenKeys keys = new PeriodicExportSeenKeys();

        assertThat(keys.isNew("GET https://example.com/a")).isTrue();
        keys.recordSeen("GET https://example.com/a");
        assertThat(keys.isNew("GET https://example.com/a")).isFalse();
    }

    @Test
    void recordSeen_ignoresBlankKeys() {
        PeriodicExportSeenKeys keys = new PeriodicExportSeenKeys();

        keys.recordSeen(null);
        keys.recordSeen("");
        keys.recordSeen("   ");

        assertThat(keys.trackedCount()).isZero();
    }

    @Test
    void claimNew_addsKeyOnlyOnce() {
        PeriodicExportSeenKeys keys = new PeriodicExportSeenKeys();

        assertThat(keys.claimNew("GET https://example.com/a")).isTrue();
        assertThat(keys.claimNew("GET https://example.com/a")).isFalse();
        assertThat(keys.isNew("GET https://example.com/a")).isFalse();
        assertThat(keys.trackedCount()).isEqualTo(1);
    }

    @Test
    void claimNew_ignoresBlankKeys() {
        PeriodicExportSeenKeys keys = new PeriodicExportSeenKeys();

        assertThat(keys.claimNew(null)).isFalse();
        assertThat(keys.claimNew("")).isFalse();
        assertThat(keys.claimNew("   ")).isFalse();
        assertThat(keys.trackedCount()).isZero();
    }

    @Test
    void clear_removesAllKeys() {
        PeriodicExportSeenKeys keys = new PeriodicExportSeenKeys();
        keys.recordSeen("a");
        keys.recordSeen("b");

        keys.clear();

        assertThat(keys.trackedCount()).isZero();
        assertThat(keys.isNew("a")).isTrue();
    }
}
