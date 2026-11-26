// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.JavaExec
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.bundling.Jar
import org.gradle.api.tasks.bundling.ZipEntryCompression
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaToolchainService
import org.gradle.jvm.toolchain.JvmVendorSpec
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.withType
import org.gradle.process.CommandLineArgumentProvider
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jlleitschuh.gradle.ktlint.KtlintExtension

/** Writes the data licence text (spec §3, [DataArtifacts.LICENSE]) to [output], one line. */
abstract class WriteDataLicenseTask : org.gradle.api.DefaultTask() {
    @get:OutputFile
    abstract val output: RegularFileProperty

    @org.gradle.api.tasks.TaskAction
    fun write() {
        output.get().asFile.writeText(DataArtifacts.LICENSE + "\n")
    }
}

/** A [JavaExec] that writes one seed archive, [archive], its declared output. */
abstract class SeedArchiveExec : JavaExec() {
    @get:OutputFile
    abstract val archive: RegularFileProperty
}

/** A [JavaExec] that writes one released seed jar's verified signed `<ts>` to [timestamp], its declared output. */
abstract class SeedTimestampExec : JavaExec() {
    @get:OutputFile
    abstract val timestamp: RegularFileProperty
}

/**
 * `data-artifact` (CONTRIBUTING §3; spec §6.5, §7.2; #145): the build of the `revokt-seed-<channel>` data artifacts.
 * Nothing it compiles is published: the project's `main` source set is the seed job's entry, compiled with
 * `friendPaths` to `revokt-engine` so it calls the engine's internal core (`SeedJob`, `buildSeed`); its `smoke` source
 * set sees only revokt-jsse's API (the public builder and its `@RevoktInternalApi` engine seam).
 *
 * Per channel, none of them part of `check` (they reach Mozilla):
 * - `writeSeed<Channel>`: the job, on Temurin 21 ([jobLauncher]), writes `build/seed/revokt-seed-<channel>.zip`;
 *   it needs `-Prevokt.seedVersion=YYYY.MM.DD` and is never up to date;
 * - `seedJar<Channel>`: the jar an app bundles, holding that archive, stored, as `revokt/seed-<channel>.zip`, the
 *   data licence text as `META-INF/LICENSE-DATA` and in the manifest, and nothing else;
 * - `verifySeedJar<Channel>` ([VerifySeedJarTask]) and `smokeLoadSeed<Channel>`, which starts a `Revokt` on the jar
 *   alone through the public builder (the sole-seed `ENFORCE` configuration, so an unreadable seed throws).
 * - `seedTimestamp<Channel>` (#308): the weekly job's floor check re-verifies the content signature of the last
 *   released seed jar, `-Prevokt.seedJar=<absolute path>`, under Mozilla's pins with the x5u valid at its signed
 *   `<ts>` (the engine's `verifySeedSignature`), and writes that `<ts>` to `-Prevokt.seedTimestampOut=<file>`
 *   (default `build/seed-timestamp/revokt-seed-<channel>.ts`); no network, never up to date.
 *
 * No Maven publication: in 0.2 a seed is a GitHub release asset with attestations, which release-seed.yml attaches
 * (the maintainer's decision, 2026-11-23). In `check`, with no network: the same chain over the committed test-signed
 * fixture (`writeTestSeed`, `testSeedJar`, `verifyTestSeedJar`, `smokeLoadTestSeed` under the fixture's test pin).
 */
class DataArtifactPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        pluginManager.apply("org.jetbrains.kotlin.jvm")
        pluginManager.apply("org.jlleitschuh.gradle.ktlint")
        pluginManager.apply("io.gitlab.arturbosch.detekt")

        applyDependencyLocking()

        extensions.configure<KotlinJvmProjectExtension> {
            jvmToolchain(Conventions.JDK_BUILD)
            compilerOptions { allWarningsAsErrors.set(true) }
        }
        val sourceSets = extensions.getByType<SourceSetContainer>()
        val smoke = sourceSets.create("smoke")

        // The job's entry and its check-path test call the engine's internals: friends of revokt-engine's jvm classes, exactly
        // as they sit on each compile classpath (the KGP mechanism a test compilation uses for its main).
        fun engineOn(configuration: String) =
            configurations.named(configuration).map { c ->
                c.incoming
                    .artifactView {
                        componentFilter { it is ProjectComponentIdentifier && it.projectPath == DataArtifacts.ENGINE_PROJECT }
                    }.files
            }
        tasks.named<KotlinCompile>("compileKotlin") { friendPaths.from(engineOn("compileClasspath")) }
        tasks.named<KotlinCompile>("compileTestKotlin") { friendPaths.from(engineOn("testCompileClasspath")) }
        // The job's classes are never packed: the jars an app bundles are the seed jars below.
        tasks.named("jar") { enabled = false }

        extensions.configure<KtlintExtension> {
            version.set(VersionCatalog.ktlint(project))
            android.set(false)
        }
        extensions.configure<DetektExtension> {
            buildUponDefaultConfig = true
            config.setFrom(rootProject.layout.projectDirectory.file("detekt.yml"))
            baseline = null
        }
        tasks.named("check") {
            dependsOn(tasks.withType<Detekt>().matching { !it.name.startsWith("detektBaseline") && it.name != "detektGenerateConfig" })
        }
        dependencies {
            "detektPlugins"(Conventions.DETEKT_RULES)
            constraints {
                add("ktlint", "ch.qos.logback:logback-core:1.5.34") { because("GHSA-jhq6-gfmj-v8fx, GHSA-p47f-322f-whfh, GHSA-qqpg-mvqg-649v") }
                add("ktlint", "ch.qos.logback:logback-classic:1.5.34") { because("keeps logback-classic aligned with logback-core") }
            }
        }
        tasks.withType<Test>().configureEach {
            useJUnitPlatform()
            configureTestLogging(project, this)
        }

        val version: Provider<String> = providers.gradleProperty(DataArtifacts.VERSION_PROPERTY)
        val jarVersion = version.getOrElse(UNSET_VERSION)
        val launcher = jobLauncher()
        val licence =
            tasks.register<WriteDataLicenseTask>("writeDataLicense") {
                description = "Writes the data licence text (spec §3) that every seed jar carries as ${DataArtifacts.LICENSE_ENTRY}."
                output.set(layout.buildDirectory.file("data-license/${DataArtifacts.LICENSE_ENTRY.substringAfterLast('/')}"))
            }

        for (channel in DataArtifacts.CHANNELS) {
            val suffix = channel.replaceFirstChar { it.uppercase() }
            val base = DataArtifacts.name(channel)
            val write =
                tasks.register<SeedArchiveExec>("writeSeed$suffix") {
                    description = "Fetches, verifies and writes the $channel seed archive from Mozilla Remote Settings (network; never in check)."
                    group = "revokt"
                    javaLauncher.set(launcher)
                    classpath = sourceSets.getByName("main").runtimeClasspath
                    mainClass.set(JOB_MAIN)
                    archive.set(layout.buildDirectory.file("seed/$base.zip"))
                    val out = archive
                    argumentProviders.add(
                        CommandLineArgumentProvider {
                            val v = version.orNull
                                ?: throw GradleException(
                                    "writeSeed$suffix needs -P${DataArtifacts.VERSION_PROPERTY}=YYYY.MM.DD, the run's UTC date (spec §7.2).",
                                )
                            listOf("--channel", channel, "--version", v, "--out", out.get().asFile.absolutePath)
                        },
                    )
                    outputs.upToDateWhen { false }
                    outputs.cacheIf { false }
                    notCompatibleWithConfigurationCache("fetches from the network at execution; never cached")
                }
            val jar = seedJar("seedJar$suffix", channel, write.flatMap { it.archive }, licence, jarVersion, "seed")
            val verify = verifySeedJar("verifySeedJar$suffix", channel, jar, write.flatMap { it.archive })
            tasks.register<JavaExec>("smokeLoadSeed$suffix") {
                description = "Starts a Revokt on the $channel seed jar alone, through the public builder, under Mozilla's pins."
                group = "revokt"
                dependsOn(verify)
                javaLauncher.set(launcher)
                classpath = smoke.runtimeClasspath + files(jar)
                mainClass.set(SMOKE_MAIN)
                args("--channel", channel)
                notCompatibleWithConfigurationCache("runs after the network write")
            }
            tasks.register<SeedTimestampExec>("seedTimestamp$suffix") {
                description = "Re-verifies a released $channel seed jar (-P${DataArtifacts.SEED_JAR_PROPERTY}) under Mozilla's pins and writes its signed <ts>."
                group = "revokt"
                javaLauncher.set(launcher)
                classpath = sourceSets.getByName("main").runtimeClasspath
                mainClass.set(TIMESTAMP_MAIN)
                timestamp.set(
                    providers
                        .gradleProperty(DataArtifacts.SEED_TIMESTAMP_OUT_PROPERTY)
                        .map { layout.projectDirectory.file(it) }
                        .orElse(layout.buildDirectory.file("seed-timestamp/$base.ts")),
                )
                val out = timestamp
                val jarPath = providers.gradleProperty(DataArtifacts.SEED_JAR_PROPERTY)
                argumentProviders.add(
                    CommandLineArgumentProvider {
                        val path = jarPath.orNull
                            ?: throw GradleException("seedTimestamp$suffix needs -P${DataArtifacts.SEED_JAR_PROPERTY}=<the released jar, an absolute path>.")
                        // Absolute only: a relative path would resolve against data/seed, not where Gradle was started.
                        if (!java.io.File(path).isAbsolute) {
                            throw GradleException("-P${DataArtifacts.SEED_JAR_PROPERTY} must be an absolute path, not '$path'.")
                        }
                        listOf("--channel", channel, "--jar", path, "--out", out.get().asFile.absolutePath)
                    },
                )
                outputs.upToDateWhen { false }
                outputs.cacheIf { false }
                notCompatibleWithConfigurationCache("reads a jar named on the command line; never cached")
            }
        }

        // The check path: the same tasks over the committed test-signed fixture, no network.
        val fixture = layout.projectDirectory.dir("src/test/resources/fixture")
        val corpus = rootProject.layout.projectDirectory.dir("corpus/clubcard")
        val writeTest =
            tasks.register<SeedArchiveExec>("writeTestSeed") {
                description = "Writes the compat seed archive from the committed test-signed fixture (no network)."
                group = "verification"
                javaLauncher.set(launcher)
                classpath = sourceSets.getByName("test").runtimeClasspath
                mainClass.set(TEST_JOB_MAIN)
                inputs.dir(fixture).withPropertyName("fixture")
                inputs.dir(corpus).withPropertyName("corpus")
                archive.set(layout.buildDirectory.file("test-seed/revokt-seed-compat.zip"))
                val out = archive
                argumentProviders.add(
                    CommandLineArgumentProvider {
                        listOf(
                            "--fixture",
                            fixture.asFile.absolutePath,
                            "--corpus",
                            corpus.asFile.absolutePath,
                            "--out",
                            out.get().asFile.absolutePath,
                        )
                    },
                )
            }
        val testJar = seedJar("testSeedJar", "compat", writeTest.flatMap { it.archive }, licence, "check", "test-seed")
        val verifyTest = verifySeedJar("verifyTestSeedJar", "compat", testJar, writeTest.flatMap { it.archive })
        val smokeTest =
            tasks.register<JavaExec>("smokeLoadTestSeed") {
                description = "Starts a Revokt on the test seed jar alone, through the public builder, under the fixture's test pin."
                group = "verification"
                dependsOn(verifyTest)
                javaLauncher.set(launcher)
                classpath = smoke.runtimeClasspath + files(testJar)
                mainClass.set(TEST_SMOKE_MAIN)
                inputs.files(testJar).withPropertyName("jar")
                inputs.file(fixture.file("pin.txt")).withPropertyName("pin")
                args("--channel", "compat", "--pin-file", fixture.file("pin.txt").asFile.absolutePath)
                val marker = layout.buildDirectory.file("test-seed/smoke-load.ok")
                outputs.file(marker)
                doLast { marker.get().asFile.writeText("ok\n") }
            }

        // SeedTimestampTest re-verifies the check path's jar through the floor check's entry, under the fixture's pin.
        tasks.named<Test>("test") {
            val testJarFile = testJar.flatMap { it.archiveFile }
            val pin = fixture.file("pin.txt")
            inputs.files(testJarFile).withPropertyName("testSeedJar")
            inputs.file(pin).withPropertyName("pin")
            jvmArgumentProviders.add(
                CommandLineArgumentProvider {
                    listOf(
                        "-Drevokt.testSeedJar=${testJarFile.get().asFile.absolutePath}",
                        "-Drevokt.testSeedPin=${pin.asFile.absolutePath}",
                    )
                },
            )
        }

        tasks.named("check") { dependsOn(smokeTest) }
    }

    /**
     * The seed jar of [channel]: [zip] stored as `revokt/seed-<channel>.zip`, the data licence text ([licence]) as
     * `META-INF/LICENSE-DATA` and in the manifest, no timestamps, a fixed entry order.
     */
    private fun Project.seedJar(
        name: String,
        channel: String,
        zip: Provider<RegularFile>,
        licence: TaskProvider<WriteDataLicenseTask>,
        version: String,
        directory: String,
    ): TaskProvider<Jar> =
        tasks.register<Jar>(name) {
            description = "Packs the $channel seed archive as ${DataArtifacts.resource(channel)} (spec §6.5)."
            group = "revokt"
            archiveFileName.set("${DataArtifacts.name(channel)}-$version.jar")
            destinationDirectory.set(layout.buildDirectory.dir(directory))
            from(zip) {
                into(DataArtifacts.resource(channel).substringBeforeLast('/'))
                rename { DataArtifacts.resource(channel).substringAfterLast('/') }
            }
            from(licence.flatMap { it.output }) { into(DataArtifacts.LICENSE_ENTRY.substringBeforeLast('/')) }
            manifest {
                attributes(
                    mapOf(
                        DataArtifacts.LICENSE_ATTRIBUTE to DataArtifacts.LICENSE,
                        "Implementation-Title" to DataArtifacts.name(channel),
                        "Implementation-Version" to version,
                    ),
                )
            }
            entryCompression = ZipEntryCompression.STORED
            isPreserveFileTimestamps = false
            isReproducibleFileOrder = true
        }

    private fun Project.verifySeedJar(
        name: String,
        channel: String,
        jar: TaskProvider<Jar>,
        zip: Provider<RegularFile>,
    ): TaskProvider<VerifySeedJarTask> =
        tasks.register<VerifySeedJarTask>(name) {
            description = "The $channel seed jar holds exactly the manifest and the stored archive the job wrote (spec §6.5)."
            group = "verification"
            this.jar.set(jar.flatMap { it.archiveFile })
            this.zip.set(zip)
            this.channel.set(channel)
        }

    /**
     * The JDK the job and its checks run on (#145): Temurin, the build's JDK 21, whatever 21.0.x is installed. The
     * weekly job (release-seed.yml) pins the exact build: it installs it from a SHA-256-checked tarball and turns
     * toolchain detection off. The deflated entries' bytes are that JDK's zlib's, so a rebuild of one changeset is
     * byte-equal on the same JDK build.
     */
    private fun Project.jobLauncher() =
        extensions.getByType<JavaToolchainService>().launcherFor {
            languageVersion.set(JavaLanguageVersion.of(Conventions.JDK_BUILD))
            vendor.set(JvmVendorSpec.ADOPTIUM)
        }

    private companion object {
        const val JOB_MAIN = "dev.revokt.seed.SeedMainKt"
        const val TEST_JOB_MAIN = "dev.revokt.seed.FixtureSeedMainKt"
        const val SMOKE_MAIN = "dev.revokt.seed.smoke.SmokeLoadKt"
        const val TEST_SMOKE_MAIN = "dev.revokt.seed.smoke.TestPinSmokeLoad"
        const val TIMESTAMP_MAIN = "dev.revokt.seed.SeedTimestampMain"

        /** The jars' version without `-Prevokt.seedVersion`: only the network tasks, which refuse to run, need one. */
        const val UNSET_VERSION = "unset"
    }
}
