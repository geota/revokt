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

// The replay's recording hooks (native/*/record-goldens.sh) pass their output paths through.
tasks.withType<Test>().configureEach {
    for (name in listOf("revokt.writeProducerInputs", "revokt.writeRecords", "revokt.writeOracleInputs")) {
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
        // About 178 000 more inputs (x509-limbo, the issuer corpus, the CT seed of revokt-corpus v5), their goldens
        // held in memory: about 6.7 GB live at the peak, measured locally on JDK 21.
        maxHeapSize = "8g"
    }
}

// Spec §9.2 Acceptance and CONTRIBUTING "Coverage": Kover branch coverage of the parser package of at least 90 % over
// the committed replay (jvmTest), part of `check`. The floor may only be raised.
kover {
    currentProject {
        createVariant("parser") { add("jvm") }
    }
    reports {
        variant("parser") {
            filters { includes { packages("dev.revokt.engine.parse") } }
            verify { rule("parser package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
    }
}

tasks.named("check") { dependsOn("koverVerifyParser") }

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
tasks.withType<Test>().configureEach {
    inputs.file(rootProject.file("gradle/oracle-matrix.properties")).withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("revokt.matrixJdks", matrixJdks)
    systemProperty("revokt.matrixConscrypt", matrixConscrypt)
}
