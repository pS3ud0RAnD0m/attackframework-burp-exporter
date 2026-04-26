package ai.attackframework.tools.burp.utils.concurrent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-level coverage of {@link EdtMonitor}'s state machine. The full probe loop relies on
 * a live AWT EDT and Swing's invokeLater queue, which is not reliably available in headless
 * test runs; these tests therefore exercise the reference-counting and tick-state seams
 * directly without relying on a real EDT.
 *
 * <p>Per-test reset runs from the constructor (JUnit 5 creates a new instance per
 * {@code @Test} method by default), matching the pattern in {@code SingleDocOutcomeRecorderTest}
 * so we avoid {@code @BeforeEach} lifecycle methods that the IDE flags as "never used".
 * Reference-counted scheduler cleanup is also covered: each test that starts the monitor
 * stops it explicitly, and the next test's constructor reset is a belt-and-braces guard.</p>
 */
class EdtMonitorTest {

    public EdtMonitorTest() {
        EdtMonitor.resetForTests();
    }

    @Test
    void start_stop_referenceCounted_endToEnd() {
        assertThat(EdtMonitor.isRunningForTests()).isFalse();
        assertThat(EdtMonitor.activeRefsForTests()).isZero();

        EdtMonitor.start();
        EdtMonitor.start();

        assertThat(EdtMonitor.isRunningForTests()).isTrue();
        assertThat(EdtMonitor.activeRefsForTests()).isEqualTo(2);

        EdtMonitor.stop();
        assertThat(EdtMonitor.isRunningForTests()).as("still running while refs > 0").isTrue();
        assertThat(EdtMonitor.activeRefsForTests()).isEqualTo(1);

        EdtMonitor.stop();
        assertThat(EdtMonitor.isRunningForTests()).isFalse();
        assertThat(EdtMonitor.activeRefsForTests()).isZero();
    }

    @Test
    void stop_withoutStart_isNoOp() {
        EdtMonitor.stop();
        EdtMonitor.stop();
        assertThat(EdtMonitor.isRunningForTests()).isFalse();
        assertThat(EdtMonitor.activeRefsForTests()).isZero();
    }

    @Test
    void tickForTests_recordsLastDump_whenProbeIsOutstandingAndOverThreshold() {
        long now = System.currentTimeMillis();
        long postedFarInThePast = now - (EdtMonitor.LAG_DUMP_THRESHOLD_MS + 5_000L);
        long ranFarInTheMorePast = postedFarInThePast - 1_000L;
        EdtMonitor.seedStateForTests(postedFarInThePast, ranFarInTheMorePast, 0L);

        EdtMonitor.tickForTests();

        assertThat(EdtMonitor.lastDumpMsForTests())
                .as("tick should have captured an EDT stack and updated lastDump")
                .isPositive();
    }

    @Test
    void tickForTests_isQuiet_whenWithinThreshold() {
        long now = System.currentTimeMillis();
        long postedRecently = now - 100L;
        long ranSlightlyEarlier = postedRecently - 5L;
        EdtMonitor.seedStateForTests(postedRecently, ranSlightlyEarlier, 0L);

        EdtMonitor.tickForTests();

        assertThat(EdtMonitor.lastDumpMsForTests())
                .as("tick under threshold must not emit a stack capture")
                .isZero();
    }

    @Test
    void wallClock_format_isStableShape() {
        String formatted = EdtMonitor.WallClock.format(0L);
        assertThat(formatted).hasSize("HH:mm:ss.SSS".length());
    }

    @Test
    void formatFullStack_includesAllFrames_andHeaderTokens() {
        StackTraceElement[] frames = new StackTraceElement[] {
                new StackTraceElement("ClassA", "methodA", "ClassA.java", 10),
                new StackTraceElement("ClassB", "methodB", "ClassB.java", 20),
                new StackTraceElement("ClassC", "methodC", "ClassC.java", 30),
        };
        String line = EdtMonitor.formatFullStack(null, frames, 4321L, 1700000000000L);
        assertThat(line)
                .startsWith("[EdtMonitor] wt=")
                .contains("lag_ms=4321")
                .contains("ClassA.methodA(ClassA.java:10)")
                .contains("ClassB.methodB(ClassB.java:20)")
                .contains("ClassC.methodC(ClassC.java:30)");
    }

    @Test
    void formatStillStuck_isCompactSingleLine() {
        String line = EdtMonitor.formatStillStuck(
                "Foo.bar(Foo.java:42)", 9999L, 1700000000000L);
        assertThat(line)
                .startsWith("[EdtMonitor] wt=")
                .contains("still-stuck top=Foo.bar(Foo.java:42)")
                .contains("lag_ms=9999")
                .doesNotContain(" | ");
    }

    @Test
    void seedLastTopFrame_isPersistedUntilReset() {
        EdtMonitor.seedLastTopFrameForTests("Foo.bar(Foo.java:1)");
        assertThat(EdtMonitor.lastTopFrameForTests()).isEqualTo("Foo.bar(Foo.java:1)");
        EdtMonitor.resetForTests();
        assertThat(EdtMonitor.lastTopFrameForTests()).isNull();
    }
}
