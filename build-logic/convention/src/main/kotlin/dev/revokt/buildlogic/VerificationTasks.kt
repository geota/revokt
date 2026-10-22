// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.security.MessageDigest

/** Every message is a remediation instruction, never a bare rule name (CONTRIBUTING §3). */
private fun fail(message: String): Nothing = throw GradleException(message)

/** Spec §3.1 item 1: each POM declares exactly the module's licence. Reads the generated `pom-default.xml` files. */
abstract class VerifyPomLicensesTask : DefaultTask() {
    @get:Input
    abstract val expectedLicense: Property<String>

    @get:Internal
    abstract val rootDir: DirectoryProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val poms: ConfigurableFileCollection

    @TaskAction
    fun verify() {
        val files = poms.files.filter { it.isFile }
        if (files.isEmpty()) fail("verifyPomLicenses: no generated POM found; run the generatePomFileFor* tasks first (maven-publish must be applied).")
        val expected = expectedLicense.get()
        for (pom in files) {
            val names = Regex("<license>\\s*<name>([^<]+)</name>", RegexOption.MULTILINE).findAll(pom.readText()).map { it.groupValues[1].trim() }.toList()
            if (names != listOf(expected)) {
                fail(
                    "verifyPomLicenses: ${pom.relativeTo(rootDir.get().asFile)} declares licences $names, expected exactly [$expected]. " +
                        "The licence is derived from the module name in Conventions.licenseOf (CONTRIBUTING §3 \"Licensing\"); " +
                        "do not add a <license> block by hand.",
                )
            }
        }
    }
}

/**
 * Spec §3 "Dependency scopes": Okio and revokt-clubcard are `implementation` (never in an api variant); kotlinx-coroutines
 * is `api` in revokt-engine; OkHttp, Ktor and bcprov appear only in their own binding; nothing under native/ or the upki
 * engine is reachable from a published module.
 */
abstract class VerifyDependencyScopesTask : DefaultTask() {
    @get:Input
    abstract val projectName: Property<String>

    /** `group:name` of every dependency declared on the api variants (apiElements / jvmApiElements). */
    @get:Input
    abstract val apiDependencies: SetProperty<String>

    /** `group:name` of every dependency declared on the runtime variants. */
    @get:Input
    abstract val runtimeDependencies: SetProperty<String>

    @TaskAction
    fun verify() {
        val name = projectName.get()
        val api = apiDependencies.get()
        val all = api + runtimeDependencies.get()

        val neverApi = listOf("com.squareup.okio:okio", "dev.revokt:revokt-clubcard")
        for (d in neverApi) {
            if (d in api) fail("verifyDependencyScopes: $d is an api dependency of $name; make it implementation (spec §3 \"Dependency scopes\": Okio internal only, MPL containment).")
        }
        if (name == "revokt-engine" && "org.jetbrains.kotlinx:kotlinx-coroutines-core" !in api && all.any { it.startsWith("org.jetbrains.kotlinx:kotlinx-coroutines") }) {
            fail("verifyDependencyScopes: kotlinx-coroutines-core must be api in revokt-engine (it appears in public signatures, spec §3).")
        }
        val bindingOnly = mapOf(
            "com.squareup.okhttp3:" to "revokt-okhttp",
            "io.ktor:" to "revokt-ktor",
            "org.bouncycastle:" to "revokt-bc",
        )
        for ((prefix, owner) in bindingOnly) {
            val offenders = all.filter { it.startsWith(prefix) }
            if (offenders.isNotEmpty() && !name.startsWith(owner)) {
                fail("verifyDependencyScopes: $name depends on $offenders; that client belongs only in $owner* (spec §3).")
            }
        }
        val forbidden = all.filter { it.startsWith("dev.revokt:revokt-engine-upki") || it.startsWith("dev.revokt:revokt-oracle") }
        if (forbidden.isNotEmpty()) fail("verifyDependencyScopes: $name reaches a CI-only oracle or engine $forbidden; oracles are tools, never shipped (CONTRIBUTING §3).")
    }
}

/** Spec §3.1 item 3: MPL-2.0 headers only inside the clubcard port package tree. */
abstract class VerifyHeaderLocationsTask : DefaultTask() {
    /** Source files only (build outputs excluded by the plugin's file tree), so no implicit task dependencies arise. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val rootDir: DirectoryProperty

    @TaskAction
    fun verify() {
        val rootDir = rootDir.get().asFile
        val allowed = Regex("""^revokt-clubcard/src/[^/]+/kotlin/.*/port/.*\.kt$""")
        val offenders = sources.files.asSequence()
            .filter { it.isFile }
            // REUSE-IgnoreStart
            .filter { it.useLines { lines -> lines.take(5).any { l -> l.contains("SPDX-License-Identifier: MPL-2.0") } } }
            // REUSE-IgnoreEnd
            .map { it.relativeTo(rootDir).path.replace(File.separatorChar, '/') }
            .filterNot { allowed.matches(it) }
            .toList()
        if (offenders.isNotEmpty()) {
            fail(
                "verifyHeaderLocations: MPL-2.0 header outside the port tree: $offenders. " +
                    "Only 1:1 translations under revokt-clubcard/src/*/kotlin/**/port/** carry MPL-2.0 (spec §3.1 item 3); " +
                    "glue under …clubcard.api and everything else is Apache-2.0.",
            )
        }
    }
}

/** corpus/ always matches corpus/manifest.sha256; an external corpus (build/corpus) when `-Prevokt.corpus` names it. */
abstract class VerifyCorpusManifestTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val corpusDir: DirectoryProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val manifest: RegularFileProperty

    @get:InputDirectory
    @get:Optional
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val externalCorpus: DirectoryProperty

    @get:Internal
    abstract val rootDir: DirectoryProperty

    @TaskAction
    fun verify() {
        verifyDir(corpusDir.get().asFile, manifest.get().asFile)
        if (externalCorpus.isPresent) {
            val ext = externalCorpus.get().asFile
            val extManifest = File(ext, "manifest.sha256")
            if (!extManifest.isFile) fail("verifyCorpusManifest: ${ext.path} has no manifest.sha256; the corpus checkout is incomplete (docs/dev/corpus.md).")
            verifyDir(ext, extManifest)
        }
    }

    private fun verifyDir(dir: File, manifestFile: File) {
        val expected = manifestFile.readLines().filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { line -> line.substringAfter("  ").trim() to line.substringBefore("  ").trim() }
        val actual = dir.walkTopDown().filter { it.isFile && it.name != "manifest.sha256" && it.name != "README.md" }
            .associate { it.relativeTo(dir).path.replace(File.separatorChar, '/') to sha256(it) }
        val missing = expected.keys - actual.keys
        val unlisted = actual.keys - expected.keys
        val changed = expected.filter { (k, v) -> actual[k] != null && actual[k] != v }.keys
        if (missing.isNotEmpty() || unlisted.isNotEmpty() || changed.isNotEmpty()) {
            fail(
                "verifyCorpusManifest: ${dir.relativeTo(rootDir.get().asFile)} disagrees with its manifest " +
                    "(missing=$missing unlisted=$unlisted changed=$changed). Corpora are data admitted through docs/dev/corpus.md: " +
                    "regenerate the manifest with `./gradlew writeCorpusManifest` only in a PR that admits the entries.",
            )
        }
    }

    private fun sha256(file: File): String = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
}

/** Writes corpus/manifest.sha256 from the files present; run only in a PR that admits entries (docs/dev/corpus.md). */
abstract class WriteCorpusManifestTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val corpusDir: DirectoryProperty

    @get:org.gradle.api.tasks.OutputFile
    abstract val manifest: RegularFileProperty

    @TaskAction
    fun write() {
        val dir = corpusDir.get().asFile
        val lines = dir.walkTopDown().filter { it.isFile && it.name != "manifest.sha256" && it.name != "README.md" }
            .map { f -> MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) } + "  " + f.relativeTo(dir).path.replace(File.separatorChar, '/') }
            .sorted().toList()
        manifest.get().asFile.writeText("# sha256  path   (relative to corpus/; regenerated only in a PR that admits entries, docs/dev/corpus.md)\n" + lines.joinToString("") { it + "\n" })
    }
}

/**
 * Resolves every resolvable configuration of its own project so `--write-locks` sees the property-gated ones
 * (purity, native, ci). Per project, because Gradle forbids cross-project resolution from a task action; the root
 * `resolveAndLockAll` aggregates them. Run with `--no-configuration-cache`.
 */
abstract class ResolveAndLockAllTask : DefaultTask() {
    @TaskAction
    fun resolveAll() {
        var count = 0
        project.configurations.filter { it.isCanBeResolved }.forEach { c ->
            runCatching { c.resolve() }.onSuccess { count++ }
                .onFailure { logger.info("resolveAndLockAll: ${project.path}:${c.name} did not resolve: ${it.message}") }
        }
        logger.lifecycle("resolveAndLockAll: ${project.path} resolved $count configurations; run with --write-locks to persist them.")
    }
}
