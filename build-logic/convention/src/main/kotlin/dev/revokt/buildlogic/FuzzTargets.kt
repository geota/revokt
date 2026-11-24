// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import kotlinx.kover.gradle.plugin.dsl.KoverProjectExtension
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.JavaExec
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaLauncher
import org.gradle.jvm.toolchain.JavaToolchainService
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.withType
import org.gradle.process.CommandLineArgumentProvider
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinCompilation
import org.jetbrains.kotlin.gradle.targets.jvm.KotlinJvmTarget
import java.io.File
import java.time.Duration

/**
 * One Jazzer `@FuzzTest` method (spec §9.1) and the libFuzzer flags its source names: `-max_len=<cap + 1>` (null when it
 * names none) and `-timeout=<s>` where it overrides the harness's 10 s.
 */
internal data class FuzzTarget(
    val module: String,
    val className: String,
    val method: String,
    val source: String,
    val maxLen: Long?,
    val timeout: Int,
) {
    /** `Class.method`: the matrix entry, the dispatch input and the artifact suffix. */
    val name: String get() = "${className.substringAfterLast('.')}.$method"

    /** The Gradle path of the module (the repository's modules sit one level below the root). */
    val project: String get() = ":" + module.replace('/', ':')
}

/** The discovery behind fuzz.yml's matrix (#115) and the nightly tier's (#119). */
internal object FuzzTargets {
    /** Spec §9.1 harness: `-timeout=10` unless the target says otherwise. */
    const val DEFAULT_TIMEOUT = 10

    /** Spec §9.1 harness: `-rss_limit_mb=2560`, ClusterFuzz's default (#321); fuzz.yml passes the same. */
    const val RSS_LIMIT_MB = 2560

    private val packageLine = Regex("""^package\s+([A-Za-z0-9_.]+)""")
    private val classLine = Regex("""^(?:(?:public|internal|open|abstract|final)\s+)*class\s+([A-Za-z_][A-Za-z0-9_]*)""")
    private val annotation = Regex("""^\s*@FuzzTest\b""")
    private val function = Regex("""\bfun\s+(`[^`]*`|[A-Za-z_][A-Za-z0-9_]*)\s*\(""")
    private val plainName = Regex("""[A-Za-z0-9_.]+""")
    private val maxLenFlag = Regex("""-max_len=(\d+)""")
    private val timeoutFlag = Regex("""-timeout=(\d+)""")

    /**
     * The targets in one Kotlin source: each method annotated `@FuzzTest` (at the start of a line, so a KDoc mention is
     * not one) of the top-level class declared above it. The flags are read from the whole file, comments included, as
     * the targets state them in their KDoc. A target's `Class.method` must be plain (`[A-Za-z0-9_.]`, no backticked
     * name): it is a Gradle test filter, a workflow input and an artifact name.
     */
    fun read(module: String, source: String, text: String): List<FuzzTarget> {
        val lines = text.lines()
        val pkg = lines.firstNotNullOfOrNull { packageLine.find(it)?.groupValues?.get(1) }
        val maxLen = single(source, "-max_len", maxLenFlag, text)?.toLong()
        val timeout = single(source, "-timeout", timeoutFlag, text)?.toInt() ?: DEFAULT_TIMEOUT
        val out = ArrayList<FuzzTarget>()
        var cls: String? = null
        var pending = false
        for (line in lines) {
            classLine.find(line)?.let { cls = it.groupValues[1] }
            val annotated = annotation.containsMatchIn(line)
            if (annotated) pending = true
            if (!pending) continue
            // The annotation's own line may hold the function too; otherwise the next `fun` is the target.
            val fn = function.find(if (annotated) line.substringAfter("@FuzzTest") else line) ?: continue
            val owner = cls ?: throw GradleException("fuzzTargets: $source has a @FuzzTest method outside a top-level class; declare it in one.")
            val target = FuzzTarget(module, listOfNotNull(pkg, owner).joinToString("."), fn.groupValues[1], source, maxLen, timeout)
            if (!plainName.matches(target.name)) {
                throw GradleException("fuzzTargets: $source has the target ${target.name}; give it a plain name ([A-Za-z0-9_.], no backticks).")
            }
            out += target
            pending = false
        }
        return out
    }

    /** Every target under [sources] (files inside `<module>/src/jvmTest/kotlin` of [rootDir]), sorted by name. */
    fun scan(rootDir: File, sources: Iterable<File>): List<FuzzTarget> {
        val root = rootDir.canonicalFile
        val targets = sources.asSequence()
            .filter { it.isFile && it.name.endsWith(".kt") }
            .flatMap { file ->
                val source = file.canonicalFile.relativeTo(root).invariantSeparatorsPath
                val module = source.substringBefore("/src/jvmTest/kotlin/", missingDelimiterValue = "")
                if (module.isEmpty()) throw GradleException("fuzzTargets: $source is not under <module>/src/jvmTest/kotlin.")
                read(module, source, file.readText())
            }
            .sortedBy { it.name }
            .toList()
        val clashes = targets.groupBy { it.name }.filterValues { it.size > 1 }
        if (clashes.isNotEmpty()) {
            throw GradleException(
                "fuzzTargets: targets share a Class.method name ${clashes.keys}: rename one, as the name keys the matrix and its artifacts.",
            )
        }
        return targets
    }

    /** The matrix for `fromJSON`: one object per target. */
    fun json(targets: List<FuzzTarget>): String =
        targets.joinToString(",\n", "[\n", "\n]\n") { t ->
            listOf(
                "name" to quote(t.name),
                "project" to quote(t.project),
                "module" to quote(t.module),
                "class" to quote(t.className),
                "method" to quote(t.method),
                "source" to quote(t.source),
                "maxLen" to (t.maxLen?.toString() ?: "null"),
                "timeout" to t.timeout.toString(),
            ).joinToString(", ", "  {", "}") { (k, v) -> "\"$k\": $v" }
        }

    private fun single(source: String, flag: String, pattern: Regex, text: String): String? {
        val values = pattern.findAll(text).map { it.groupValues[1] }.toSet()
        if (values.size > 1) throw GradleException("fuzzTargets: $source names $flag ${values.sorted()}: one value per file (split the targets).")
        return values.singleOrNull()
    }

    private fun quote(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}

/** Writes [FuzzTargets.json] for every `@FuzzTest` method in the modules' jvmTest sources and lists them. */
abstract class FuzzTargetsTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val rootDir: DirectoryProperty

    @get:OutputFile
    abstract val output: RegularFileProperty

    @TaskAction
    fun write() {
        val targets = FuzzTargets.scan(rootDir.get().asFile, sources.files)
        for (t in targets) {
            logger.lifecycle("${t.name} (${t.project}, -max_len=${t.maxLen ?: "unset"}, -timeout=${t.timeout})")
            if (t.maxLen == null) logger.warn("fuzzTargets: ${t.source} names no -max_len; spec §9.1 runs each target at its cap + 1.")
        }
        output.get().asFile.apply { parentFile.mkdirs() }.writeText(FuzzTargets.json(targets))
    }
}

internal fun Project.registerFuzzTargets(): TaskProvider<FuzzTargetsTask> =
    tasks.register<FuzzTargetsTask>("fuzzTargets") {
        description = "Lists every Jazzer @FuzzTest method with its §9.1 flags into build/fuzz/targets.json (fuzz.yml's matrix)."
        group = "revokt"
        rootDir.set(layout.projectDirectory)
        sources.from(subprojects.map { it.layout.projectDirectory.dir("src/jvmTest/kotlin").asFileTree.matching { include("**/*.kt") } })
        output.set(layout.buildDirectory.file("fuzz/targets.json"))
    }

/**
 * `fuzzMinimize` (fuzz.yml, #115): libFuzzer's `-minimize_crash=1` over one crash, timeout or oom input (it treats any
 * non-zero exit as the crash), so a finding fits a draft advisory. It runs Jazzer's standalone driver, which
 * re-launches the JVM for each minimisation step, on the target's static `fuzzerTestOneInput` with the jvmTest
 * classpath, in the §9.1 harness JVM (`-Xmx256m`, `-rss_limit_mb=2560`, and jvmTest's system properties and JVM
 * arguments) on the tests' JDK. Properties:
 * `revokt.fuzzClass`, `revokt.fuzzInput`, `revokt.fuzzOutput` (libFuzzer rewrites it with each smaller crashing input),
 * `revokt.fuzzTimeout` (the target's `-timeout`, default 10), `revokt.fuzzSeconds` (each step's search, default 10) and
 * `revokt.fuzzBudget` (the whole task, default 300 s: libFuzzer's loop has no bound of its own, so the task times out
 * and the output holds the smallest input found so far). Jazzer's re-launched JVMs outlive a timeout; fuzz.yml kills
 * them before it encrypts the output.
 *
 * `fuzzMerge` (fuzz.yml's weekly prune, #265): libFuzzer's `-merge=1` of one target's corpus into a fresh directory,
 * which keeps the smallest set of units that covers the corpus's features; units are named by their SHA-1, as the
 * corpus's own are. The same driver, classpath and harness JVM, with `revokt.fuzzClass`, `revokt.fuzzCorpus` (the
 * corpus directory), `revokt.fuzzMerged` (the fresh output directory, created empty if absent), `revokt.fuzzTimeout`,
 * `revokt.fuzzMaxLen` (the target's `-max_len`, unset for libFuzzer's default) and `revokt.fuzzBudget` (default
 * 1800 s). A unit that crashes or times out is left out by libFuzzer; fuzz.yml keeps a target's corpus unchanged then.
 *
 * `fuzzReplay` (fuzz.yml's reproduce step, #321): runs one input once, alone, through the same driver, classpath and
 * harness JVM, and fails if the target fails on it. fuzz.yml files an advisory only for an input that fails again
 * here while the empty input passes. Properties: `revokt.fuzzClass`, `revokt.fuzzInput`, `revokt.fuzzOutput` (where
 * libFuzzer writes a failing input, `-exact_artifact_path`, so no file is named by the input's hash),
 * `revokt.fuzzTimeout`, `revokt.fuzzMaxLen` (unset for libFuzzer's default) and `revokt.fuzzBudget` (default 300 s).
 */
internal fun Project.registerFuzzDrivers() {
    val property = { name: String -> providers.gradleProperty("revokt.$name") }
    val testJdk = providers.gradleProperty("revokt.testJdk").map { it.toInt() }.orElse(Conventions.JDK_BUILD)
    val launcher = extensions.getByType<JavaToolchainService>().launcherFor { languageVersion.set(testJdk.map { JavaLanguageVersion.of(it) }) }
    // Only for a module with a `jvm` target, selected lazily: a KMP module without one gets no task.
    extensions.getByType<KotlinMultiplatformExtension>().targets.withType<KotlinJvmTarget>().matching { it.name == "jvm" }.configureEach {
        registerFuzzMinimizeTask(compilations.getByName("test"), property, launcher)
        registerFuzzMergeTask(compilations.getByName("test"), property, launcher)
        registerFuzzReplayTask(compilations.getByName("test"), property, launcher)
    }
}

/**
 * The jvmTest JVM's system properties, JVM arguments and argument providers (the clubcard corpus path, the native
 * access flag), so the standalone driver runs a target in the JVM its `@FuzzTest` gets (#321: without the corpus path
 * `StoreModelFuzzTest` failed on every input, the empty one too). The heap stays the harness's `-Xmx256m`, and Kover's
 * coverage agent stays out: it is not part of the harness, and its report, an output, would let Gradle skip the task
 * as up to date. jvmTest is read when this task is configured, after the module's build script has configured it.
 */
private fun JavaExec.likeJvmTest() {
    val test = project.tasks.named<Test>("jvmTest").get()
    systemProperties(test.systemProperties)
    jvmArgs(test.jvmArgs.orEmpty())
    jvmArgumentProviders.addAll(test.jvmArgumentProviders.filterNot { it.javaClass.name.startsWith("kotlinx.kover.") })
}

private fun Project.registerFuzzMinimizeTask(
    test: KotlinCompilation<*>,
    property: (String) -> Provider<String>,
    launcher: Provider<JavaLauncher>,
) {
    tasks.register<JavaExec>("fuzzMinimize") {
        description = "Minimises one Jazzer finding input with libFuzzer's -minimize_crash=1 (fuzz.yml, #115)."
        group = "revokt"
        classpath = files(test.output.allOutputs, test.runtimeDependencyFiles ?: files())
        mainClass.set("com.code_intelligence.jazzer.Jazzer")
        maxHeapSize = "256m"
        javaLauncher.set(launcher)
        likeJvmTest()
        val cls = property("fuzzClass")
        val input = property("fuzzInput")
        val output = property("fuzzOutput")
        val perInput = property("fuzzTimeout").orElse(FuzzTargets.DEFAULT_TIMEOUT.toString())
        val seconds = property("fuzzSeconds").orElse("10")
        timeout.set(property("fuzzBudget").orElse("300").map { Duration.ofSeconds(it.toLong()) })
        argumentProviders.add(
            CommandLineArgumentProvider {
                listOf(
                    "--target_class=${cls.get()}",
                    "--instrumentation_includes=dev.revokt.**",
                    "-minimize_crash=1",
                    "-max_total_time=${seconds.get()}",
                    "-timeout=${perInput.get()}",
                    "-rss_limit_mb=${FuzzTargets.RSS_LIMIT_MB}",
                    "-exact_artifact_path=${output.get()}",
                    input.get(),
                )
            },
        )
    }
}

private fun Project.registerFuzzMergeTask(
    test: KotlinCompilation<*>,
    property: (String) -> Provider<String>,
    launcher: Provider<JavaLauncher>,
) {
    tasks.register<JavaExec>("fuzzMerge") {
        description = "Merges one Jazzer target's corpus into a fresh directory with libFuzzer's -merge=1 (fuzz.yml, #265)."
        group = "revokt"
        classpath = files(test.output.allOutputs, test.runtimeDependencyFiles ?: files())
        mainClass.set("com.code_intelligence.jazzer.Jazzer")
        maxHeapSize = "256m"
        javaLauncher.set(launcher)
        likeJvmTest()
        val cls = property("fuzzClass")
        val corpus = property("fuzzCorpus")
        val merged = property("fuzzMerged")
        val perInput = property("fuzzTimeout").orElse(FuzzTargets.DEFAULT_TIMEOUT.toString())
        val maxLen = property("fuzzMaxLen")
        timeout.set(property("fuzzBudget").orElse("1800").map { Duration.ofSeconds(it.toLong()) })
        doFirst { File(merged.get()).mkdirs() }
        argumentProviders.add(
            CommandLineArgumentProvider {
                listOfNotNull(
                    "--target_class=${cls.get()}",
                    "--instrumentation_includes=dev.revokt.**",
                    "-merge=1",
                    "-timeout=${perInput.get()}",
                    "-rss_limit_mb=${FuzzTargets.RSS_LIMIT_MB}",
                    maxLen.orNull?.let { "-max_len=$it" },
                    merged.get(),
                    corpus.get(),
                )
            },
        )
    }
}

private fun Project.registerFuzzReplayTask(
    test: KotlinCompilation<*>,
    property: (String) -> Provider<String>,
    launcher: Provider<JavaLauncher>,
) {
    tasks.register<JavaExec>("fuzzReplay") {
        description = "Replays one Jazzer input alone and fails if the target fails on it (fuzz.yml, #321)."
        group = "revokt"
        classpath = files(test.output.allOutputs, test.runtimeDependencyFiles ?: files())
        mainClass.set("com.code_intelligence.jazzer.Jazzer")
        maxHeapSize = "256m"
        javaLauncher.set(launcher)
        likeJvmTest()
        val cls = property("fuzzClass")
        val input = property("fuzzInput")
        val output = property("fuzzOutput")
        val perInput = property("fuzzTimeout").orElse(FuzzTargets.DEFAULT_TIMEOUT.toString())
        val maxLen = property("fuzzMaxLen")
        timeout.set(property("fuzzBudget").orElse("300").map { Duration.ofSeconds(it.toLong()) })
        argumentProviders.add(
            CommandLineArgumentProvider {
                // A file (not a directory) as the only input: libFuzzer runs it once and exits non-zero if it fails.
                listOfNotNull(
                    "--target_class=${cls.get()}",
                    "--instrumentation_includes=dev.revokt.**",
                    "-timeout=${perInput.get()}",
                    "-rss_limit_mb=${FuzzTargets.RSS_LIMIT_MB}",
                    maxLen.orNull?.let { "-max_len=$it" },
                    "-exact_artifact_path=${output.get()}",
                    input.get(),
                )
            },
        )
    }
}

/**
 * A fuzzing run (`JAZZER_FUZZ` set, as Jazzer reads it; fuzz.yml) gets no Kover coverage agent (#321): coverage is not
 * part of the §9.1 harness, and its agent adds to the JVM's footprint under `-rss_limit_mb`. OSS-Fuzz, too, keeps its
 * coverage builds apart from its fuzzing builds. The PR tier's replay of the committed inputs (`JAZZER_FUZZ` unset)
 * keeps its coverage.
 */
internal fun Project.disableKoverWhileFuzzing() {
    val jazzerFuzz = providers.environmentVariable("JAZZER_FUZZ").orNull?.lowercase()
    if (jazzerFuzz == "1" || jazzerFuzz == "true" || jazzerFuzz == "yes") {
        extensions.configure<KoverProjectExtension> { currentProject { instrumentation { disabledForAll.set(true) } } }
    }
}
