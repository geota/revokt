// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import org.pitest.mutationtest.config.PluginServices;
import org.pitest.mutationtest.config.ReportOptions;
import org.pitest.mutationtest.tooling.AnalysisResult;
import org.pitest.mutationtest.tooling.EntryPoint;
import org.pitest.testapi.TestGroupConfig;
import org.pitest.util.Glob;
import org.pitest.util.Verbosity;

/**
 * Runs Pitest over revokt's compiled JVM classes through pitest-entry's API (#215), with no command-line parser, so
 * the build needs neither pitest-command-line nor its jopt-simple, HTML report and template dependencies. Launched by
 * the {@code pitestJvm} task as a single-file source program ({@code java -cp <pitest> PitestRunner.java <args file>}).
 *
 * <p>The arguments file holds one {@code key=value} per line, a key repeated for a list: {@code reportDir},
 * {@code threads}, {@code targetClass}, {@code targetTest}, {@code sourceDir}, {@code classPath}, {@code codePath},
 * {@code jvmArg}, {@code avoidCallsTo}. Values are taken whole, so a JVM argument may hold commas.
 */
public final class PitestRunner {
    public static void main(String[] args) throws Exception {
        Map<String, List<String>> a = new java.util.LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            a.computeIfAbsent(line.substring(0, eq), k -> new ArrayList<>()).add(line.substring(eq + 1));
        }
        ReportOptions o = new ReportOptions();
        o.setReportDir(one(a, "reportDir"));
        o.setNumberOfThreads(Integer.parseInt(one(a, "threads")));
        o.setTargetClasses(all(a, "targetClass"));
        List<Predicate<String>> tests = new ArrayList<>();
        for (String t : all(a, "targetTest")) tests.add(new Glob(t));
        o.setTargetTests(tests);
        List<Path> sources = new ArrayList<>();
        for (String s : all(a, "sourceDir")) sources.add(Path.of(s));
        o.setSourceDirs(sources);
        o.setClassPathElements(all(a, "classPath"));
        o.setCodePaths(all(a, "codePath"));
        o.addChildJVMArgs(all(a, "jvmArg"));
        // Calls to Kotlin's own null checks (Intrinsics) are generated, not written: mutating them is noise.
        o.setLoggingClasses(all(a, "avoidCallsTo"));
        o.addOutputFormats(List.of("XML", "CSV"));
        o.setShouldCreateTimestampedReports(false);
        o.setVerbosity(Verbosity.DEFAULT);
        o.setTimeoutConstant(4000);
        o.setTimeoutFactor(1.25f);
        o.setMutationEngine("gregor");
        o.setFailWhenNoMutations(true);
        o.setIncludeLaunchClasspath(true);
        // The command line's defaults, which ReportOptions leaves null.
        o.setGroupConfig(new TestGroupConfig(List.of(), List.of()));
        o.setExcludedRunners(List.of());
        o.setIncludedTestMethods(List.of());
        o.setExcludedClasses(List.of());
        o.setExcludedMethods(List.of());
        o.setExcludedTestClasses(List.of());
        o.setMutators(List.of());
        o.setFeatures(List.of());
        AnalysisResult r = new EntryPoint().execute(new File("."), o, PluginServices.makeForContextLoader(), Collections.emptyMap());
        // EntryPoint has printed the statistics; the XML report is what the summary reads.
        if (r.getError().isPresent()) throw r.getError().get();
    }

    private static List<String> all(Map<String, List<String>> a, String key) {
        return a.getOrDefault(key, List.of());
    }

    private static String one(Map<String, List<String>> a, String key) {
        List<String> v = all(a, key);
        if (v.size() != 1) throw new IllegalArgumentException("exactly one " + key + " expected, got " + v);
        return v.get(0);
    }
}
