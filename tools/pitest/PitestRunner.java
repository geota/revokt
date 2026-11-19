// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.pitest.bytecode.analysis.ClassTree;
import org.pitest.mutationtest.build.InterceptorParameters;
import org.pitest.mutationtest.build.InterceptorType;
import org.pitest.mutationtest.build.MutationInterceptor;
import org.pitest.mutationtest.build.MutationInterceptorFactory;
import org.pitest.mutationtest.config.PluginServices;
import org.pitest.mutationtest.config.ReportOptions;
import org.pitest.mutationtest.config.Services;
import org.pitest.mutationtest.engine.Mutater;
import org.pitest.mutationtest.engine.MutationDetails;
import org.pitest.plugin.Feature;
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
 * {@code jvmArg}. Values are taken whole, so a JVM argument may hold commas.
 *
 * <p>One filter is added to Pitest's own: {@link KotlinNullChecks}, which drops the mutants that remove a call to one of
 * the Kotlin compiler's generated null checks, and nothing else on their lines.
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
        // No avoidCallsTo: it drops every mutant on a line calling into kotlin.jvm.internal, `==` (Intrinsics.areEqual)
        // included, which hid real guards. KotlinNullChecks drops only the generated null checks.
        o.setLoggingClasses(List.of());
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
        PluginServices plugins = new PluginServices(new WithKotlinNullChecks(Thread.currentThread().getContextClassLoader()));
        AnalysisResult r = new EntryPoint().execute(new File("."), o, plugins, Collections.emptyMap());
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

    /** The context class loader's plugins, plus {@link KotlinNullChecks}. */
    private static final class WithKotlinNullChecks implements Services {
        private final ClassLoader loader;

        WithKotlinNullChecks(ClassLoader loader) {
            this.loader = loader;
        }

        @Override
        public <S> Collection<S> load(Class<S> type) {
            List<S> found = new ArrayList<>();
            java.util.ServiceLoader.load(type, loader).forEach(found::add);
            if (type == MutationInterceptorFactory.class) found.add(type.cast(new KotlinNullChecks()));
            return found;
        }
    }

    /**
     * Drops a mutant whose instruction is a call to one of the null checks the Kotlin compiler generates:
     * {@code Intrinsics.checkNotNull*} ({@code !!}, platform-type values, parameters) and
     * {@code throwUninitializedPropertyAccessException} ({@code lateinit}). Removing such a call is noise, since no
     * test of Kotlin code can pass the null it guards against. Every other mutant on the same line is kept, so a guard
     * written with {@code ==} ({@code Intrinsics.areEqual}) is still mutated.
     */
    static final class KotlinNullChecks implements MutationInterceptorFactory, MutationInterceptor {
        private static final String INTRINSICS = "kotlin/jvm/internal/Intrinsics";
        private ClassTree tree;

        static boolean isNullCheck(AbstractInsnNode insn) {
            if (!(insn instanceof MethodInsnNode call) || !call.owner.equals(INTRINSICS)) return false;
            return call.name.startsWith("checkNotNull") || call.name.equals("throwUninitializedPropertyAccessException");
        }

        @Override
        public MutationInterceptor createInterceptor(InterceptorParameters params) {
            return new KotlinNullChecks();
        }

        @Override
        public Feature provides() {
            return Feature.named("FKNULLCHECKS")
                    .withOnByDefault(true)
                    .withDescription("Filters mutants that remove a call to a Kotlin-generated null check");
        }

        @Override
        public String description() {
            return "Kotlin generated null-check filter";
        }

        @Override
        public InterceptorType type() {
            return InterceptorType.FILTER;
        }

        @Override
        public void begin(ClassTree clazz) {
            tree = clazz;
        }

        @Override
        public Collection<MutationDetails> intercept(Collection<MutationDetails> mutations, Mutater m) {
            List<MutationDetails> kept = new ArrayList<>();
            for (MutationDetails d : mutations) {
                Optional<AbstractInsnNode> insn =
                        tree.method(d.getId().getLocation()).flatMap(t -> t.instructionForIndex(d.getInstructionIndex()));
                if (insn.isEmpty() || !isNullCheck(insn.get())) kept.add(d);
            }
            return kept;
        }

        @Override
        public void end() {
            tree = null;
        }
    }
}
