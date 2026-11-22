// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

import kotlinx.kover.gradle.plugin.dsl.CoverageUnit
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import java.util.Properties

plugins {
    id("revokt.kmp-library")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(project(":revokt-clubcard"))
            implementation(libs.okio)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        jvmTest.dependencies {
            implementation(libs.kotlin.test.junit5)
            implementation(project.dependencies.platform(libs.junit.bom))
            implementation(libs.junit.jupiter)
            implementation(libs.jazzer.junit)
            implementation(libs.conscrypt.openjdk.uber)
            runtimeOnly(libs.junit.platform.launcher)
        }
    }
}

val corpus: File? = providers.gradleProperty("revokt.corpus").orNull?.let { rootProject.file(it) }

// The replay's recording hooks (native/*/record-goldens.sh) pass their output paths through, and
// `-Drevokt.storeModel.seed=<n>` replays one seed of StoreModelTest.
tasks.withType<Test>().configureEach {
    val passed =
        listOf(
            "revokt.writeProducerInputs",
            "revokt.writeRecords",
            "revokt.writeOracleInputs",
            "revokt.storeModel.seed",
        )
    for (name in passed) {
        providers.systemProperty(name).orNull?.let { systemProperty(name, it) }
    }
    // The zlint pin test reads the pin: go.mod is an input, so a bump that touches only go.mod re-runs it, and its
    // path reaches the test without entering the cache key.
    jvmArgumentProviders.add(ZlintGoMod(rootProject.file("native/zlint-oracle/go.mod")))
    // Oracle 2 (Conscrypt) loads its JNI library; JDK 24+ warn and a later release blocks it without this (JDK 17+).
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    // Oracle 1 is the test JDK, whose patch can change an outcome; Gradle keys a toolchain by its language version only,
    // so a cached result from another patch would stand in for this one.
    inputs.property("testJavaRuntimeVersion", javaLauncher.map { it.metadata.javaRuntimeVersion })
    inputs.property("testJavaVendor", javaLauncher.map { it.metadata.vendor })
    // The large corpus (docs/dev/corpus.md): `-Prevokt.corpus=<checkout>` adds its inputs, goldens and records to the
    // replay. Its tree is an input; its path reaches the tests without entering the cache key.
    // The committed fixture generation, whose filters' index maps the producer SPKI check covers (spec §9.2).
    jvmArgumentProviders.add(ClubcardCorpus(rootProject.file("corpus/clubcard")))
    corpus?.let {
        jvmArgumentProviders.add(CorpusDir(it, fileTree(it) { exclude(".git", ".git/**") }))
        // About 178 000 more inputs (x509-limbo, the issuer corpus, the CT seed of revokt-corpus v6), their goldens
        // held in memory: about 6.7 GB live at the peak, measured locally on JDK 21.
        maxHeapSize = "8g"
    }
}

// Spec §9.1 harness: a fuzzing run (JAZZER_FUZZ set, as Jazzer reads it; fuzz.yml) gets -Xmx256m, so the JVM stays under
// the -rss_limit_mb=1024 the workflow passes.
val jazzerFuzz = providers.environmentVariable("JAZZER_FUZZ").orNull?.lowercase()
if (jazzerFuzz == "1" || jazzerFuzz == "true" || jazzerFuzz == "yes") {
    tasks.named<Test>("jvmTest") { maxHeapSize = "256m" }
}

// Spec §9.2 Acceptance and CONTRIBUTING "Coverage": Kover branch coverage of each parser package of at least 90 % over
// the committed tests (jvmTest), part of `check`: the certificate parser, the C2SP index reader (#86), the CRLite
// generation (#90), the JSON tokenizer and canonical JSON (#92), the content-signature payload and raw-to-DER
// conversion (#125) and, under the parser's floor, the seed archive reader (#138). The path walker, the store, the
// updater and the fetch layer have floors a little under their measured branch coverage (#161: walker 98.96 %, store
// 94.26 % at f2c54fc; #212: update 90.66 %, fetch 95.87 % at 22b2191, as koverVerify computes it). The floors may only
// be raised.
kover {
    currentProject {
        createVariant("parser") { add("jvm") }
        createVariant("c2sp") { add("jvm") }
        createVariant("crlite") { add("jvm") }
        createVariant("json") { add("jvm") }
        createVariant("verify") { add("jvm") }
        createVariant("walker") { add("jvm") }
        createVariant("store") { add("jvm") }
        createVariant("update") { add("jvm") }
        createVariant("fetch") { add("jvm") }
    }
    reports {
        variant("parser") {
            filters { includes { packages("dev.revokt.engine.parse", "dev.revokt.engine.seed.parse") } }
            verify { rule("parser package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
        variant("c2sp") {
            filters { includes { packages("dev.revokt.engine.c2sp") } }
            verify { rule("c2sp package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
        variant("crlite") {
            filters {
                includes {
                    packages("dev.revokt.engine.crlite")
                    classes("dev.revokt.KotlinRevocationEngine", "dev.revokt.KotlinRevocationEngine$*")
                }
            }
            verify { rule("crlite package and engine branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
        variant("json") {
            filters { includes { packages("dev.revokt.engine.json") } }
            verify { rule("json package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
        variant("verify") {
            filters { includes { packages("dev.revokt.engine.verify") } }
            verify { rule("content-signature package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
        variant("walker") {
            filters { includes { packages("dev.revokt.engine.walker") } }
            verify { rule("walker package branch coverage") { minBound(98, CoverageUnit.BRANCH) } }
        }
        variant("store") {
            filters { includes { packages("dev.revokt.engine.store") } }
            verify { rule("store package branch coverage") { minBound(93, CoverageUnit.BRANCH) } }
        }
        variant("update") {
            filters { includes { packages("dev.revokt.engine.update") } }
            verify { rule("update package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
        variant("fetch") {
            filters { includes { packages("dev.revokt.engine.fetch") } }
            verify { rule("fetch package branch coverage") { minBound(95, CoverageUnit.BRANCH) } }
        }
    }
}

tasks.named("check") {
    dependsOn(
        "koverVerifyParser",
        "koverVerifyC2sp",
        "koverVerifyCrlite",
        "koverVerifyJson",
        "koverVerifyVerify",
        "koverVerifyWalker",
        "koverVerifyStore",
        "koverVerifyUpdate",
        "koverVerifyFetch",
    )
}

class ClubcardCorpus(
    @get:InputDirectory @get:PathSensitive(PathSensitivity.RELATIVE) val dir: File,
) : CommandLineArgumentProvider {
    override fun asArguments(): List<String> = listOf("-Drevokt.clubcardCorpus=${dir.absolutePath}")
}

class CorpusDir(
    @get:Internal val dir: File,
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) val files: FileTree,
) : CommandLineArgumentProvider {
    override fun asArguments(): List<String> = listOf("-Drevokt.corpus=${dir.absolutePath}")
}

class ZlintGoMod(
    @get:InputFile @get:PathSensitive(PathSensitivity.RELATIVE) val file: File,
) : CommandLineArgumentProvider {
    override fun asArguments(): List<String> = listOf("-Drevokt.zlintGoMod=${file.absolutePath}")
}

// The Conscrypt dimension of the §9.2 matrix (gradle/oracle-matrix.properties): jvmTest runs oracle 2 on the catalog's
// `conscrypt`; this task reruns the Conscrypt-dependent tests (and the recording hooks) on `conscrypt-previous`, with that
// uber jar in place of the current one. Part of `check`.
val conscryptPrevious =
    configurations.register("conscryptPrevious") {
        isCanBeConsumed = false
        isCanBeResolved = true
        isTransitive = false
    }
dependencies { add("conscryptPrevious", libs.conscrypt.openjdk.uber.previous) }

// verifyOracleMatrix (build-logic VerificationTasks.kt, WIRED_CONSCRYPT) checks the matrix names exactly the two
// catalog keys this build wires: `conscrypt` (jvmTest) and `conscrypt-previous` (here). Change both together.
val conscryptPreviousTests = listOf("ConscryptReplayTest", "RecordsTest", "Oracle3aTest", "ProducerGoldensWriterTest")

val jvmTestConscryptPrevious =
    tasks.register<Test>("jvmTestConscryptPrevious") {
        description = "The Conscrypt-dependent replay and records on the matrix's previous Conscrypt minor."
        group = "verification"
        val compilation = kotlin.jvm().compilations.getByName("test")
        testClassesDirs = compilation.output.classesDirs
        val withoutConscrypt =
            configurations.named("jvmTestRuntimeClasspath").map { runtime ->
                runtime.incoming
                    .artifactView {
                        componentFilter { !(it is ModuleComponentIdentifier && it.group == "org.conscrypt") }
                    }.files
            }
        classpath = compilation.output.allOutputs + files(withoutConscrypt) + files(conscryptPrevious)
        useJUnitPlatform()
        // Each takes the corpus heap; side by side they and Gradle's daemon outgrow a 16 GB CI runner (#15: v5's 8 GB).
        mustRunAfter(tasks.named("jvmTest"))
        filter { for (name in conscryptPreviousTests) includeTestsMatching("*.$name") }
        val results = reports.junitXml.outputLocation
        val classes = conscryptPreviousTests
        val narrowed =
            gradle.startParameter.taskRequests.any { r -> r.args.any { it == "--tests" || it.startsWith("--tests=") } }
        doLast {
            // A renamed class would drop out of the filter silently: each must have run, unless --tests narrowed it.
            if (!narrowed) {
                val ran =
                    results
                        .get()
                        .asFile
                        .listFiles()
                        .orEmpty()
                        .map { it.name }
                val missing = classes.filter { name -> ran.none { it.endsWith(".$name.xml") } }
                check(missing.isEmpty()) { "jvmTestConscryptPrevious ran no $missing: update its filter" }
            }
        }
    }

tasks.named("check") { dependsOn(jvmTestConscryptPrevious) }

// The matrix's versions, so the records writer prunes oracle entries of versions that have left it.
val oracleMatrix =
    Properties().apply { rootProject.file("gradle/oracle-matrix.properties").reader().use { load(it) } }
val matrixJdks = oracleMatrix.getProperty("jdk").orEmpty()
val matrixConscrypt =
    oracleMatrix
        .getProperty("conscrypt")
        .orEmpty()
        .split(',')
        .map {
            it.trim()
        }.filter { it.isNotEmpty() }
        .joinToString(",") {
            versionCatalogs
                .named("libs")
                .findVersion(it)
                .orElseThrow {
                    GradleException("gradle/oracle-matrix.properties names Conscrypt key '$it', not a catalog version")
                }.requiredVersion
        }
val projectVersion = version.toString()
tasks.withType<Test>().configureEach {
    inputs.file(rootProject.file("gradle/oracle-matrix.properties")).withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("revokt.matrixJdks", matrixJdks)
    systemProperty("revokt.matrixConscrypt", matrixConscrypt)
    // The policy's current minor must be this build's (RevoktPolicyTest; spec §4 flippedIn grace rules).
    systemProperty("revokt.version", projectVersion)
}

// Mutation testing (#215, docs/dev/mutation-testing.md): Pitest over the JVM classes of the critical packages, run by
// `./gradlew :revokt-engine:pitestJvm` and the pitest workflow (dispatch or weekly), never by `check` or a PR. The Gradle
// Pitest plugin does not support Kotlin Multiplatform (it configures only under the `java` plugin), so the task runs
// tools/pitest/PitestRunner.java, a single-file program over pitest-entry's API, on the jvmTest classpath and JVM.
// `-Prevokt.pitest.packages=a,b` narrows it; the report is build/reports/pitest/mutations.xml (and .csv).
val pitest =
    configurations.register("pitest") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }
dependencies {
    add("pitest", libs.pitest.entry)
    add("pitest", libs.pitest.junit5.plugin)
}

val pitestPackages =
    providers
        .gradleProperty("revokt.pitest.packages")
        .orElse("update,store,fetch,verify,walker")
        .map { list -> list.split(',').map { it.trim() }.filter { it.isNotEmpty() } }

val pitestJvm =
    tasks.register<Exec>("pitestJvm") {
        description = "Pitest over the JVM classes of the critical packages (#215); never part of check."
        group = "verification"
        val test = tasks.named<Test>("jvmTest")
        dependsOn("jvmTestClasses")
        val tool = pitest
        val runner = rootProject.file("tools/pitest/PitestRunner.java")
        val reportDir = layout.buildDirectory.dir("reports/pitest")
        val argsFile = layout.buildDirectory.file("pitest/args.txt")
        val main = layout.buildDirectory.dir("classes/kotlin/jvm/main")
        val sources = listOf("src/commonMain/kotlin", "src/jvmMain/kotlin").map { layout.projectDirectory.dir(it) }
        inputs.files(tool)
        inputs.file(runner)
        outputs.dir(reportDir)
        // A mutation run is asked for, never cached: its inputs are every class and test of the packages.
        outputs.upToDateWhen { false }
        notCompatibleWithConfigurationCache("assembles its arguments from the jvmTest task at execution")
        doFirst {
            val t = test.get()
            val packages = pitestPackages.get()
            val lines = ArrayList<String>()
            lines += "reportDir=" + reportDir.get().asFile.absolutePath
            lines += "threads=" + (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 4)
            for (p in packages) {
                lines += "targetClass=dev.revokt.engine.$p.*"
                lines += "targetTest=dev.revokt.engine.$p.*"
            }
            for (d in sources) lines += "sourceDir=" + d.asFile.absolutePath
            lines += "codePath=" + main.get().asFile.absolutePath
            for (f in t.classpath.files + tool.get().files) lines += "classPath=" + f.absolutePath
            for (a in t.allJvmArgs.filter { it.startsWith("-D") }) lines += "jvmArg=$a"
            lines += "jvmArg=-Xmx2g"
            argsFile.get().asFile.apply {
                parentFile.mkdirs()
                writeText(lines.joinToString("\n", postfix = "\n"))
            }
            executable =
                t.javaLauncher
                    .get()
                    .executablePath.asFile.absolutePath
            args("-cp", tool.get().asPath, runner.absolutePath, argsFile.get().asFile.absolutePath)
        }
    }
