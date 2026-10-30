// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import kotlinx.validation.ApiValidationExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.register

/**
 * Root conventions: the API-dump validator with the opt-in markers (spec §3.1 item 4), the repository-wide
 * verification tasks (CONTRIBUTING §3, §6) and the `check` wiring that makes them gates.
 */
class RootPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        require(this == rootProject) { "revokt.root applies to the root project only" }

        pluginManager.apply("base")
        pluginManager.apply("org.jetbrains.kotlinx.binary-compatibility-validator")
        pluginManager.apply("org.jetbrains.kotlinx.kover")
        // The root Kover report aggregates the published modules (the coverage gate reads build/reports/kover/report.xml).
        afterEvaluate {
            subprojects.filter { it.plugins.hasPlugin("org.jetbrains.kotlinx.kover") }.forEach { sub ->
                dependencies.add("kover", sub)
            }
        }

        extensions.configure<ApiValidationExtension> {
            nonPublicMarkers.add(Conventions.MARKER_INTERNAL)
            nonPublicMarkers.add(Conventions.MARKER_TESTING)
            nonPublicMarkers.add(Conventions.MARKER_CLUBCARD_INTERNAL)
            ignoredProjects.add("revokt-bom")
            @Suppress("OPT_IN_USAGE")
            klib { enabled = false }
        }

        val specStatus = tasks.register<SpecStatusTask>("specStatus") {
            description = "Regenerates docs/dev/status.md from the spec's fixture and deliverable inventory and the test tree."
            group = "revokt"
            spec.set(layout.projectDirectory.file("docs/spec/revokt-spec.md"))
            testRoots.from(subprojects.map { it.layout.projectDirectory.dir("src") })
            output.set(layout.projectDirectory.file("docs/dev/status.md"))
            ctSeedGap.set(layout.projectDirectory.file("revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/ct-seed-gap.tsv"))
            checkOnly.set(false)
            rootDir.set(layout.projectDirectory)
        }
        val specStatusCheck = tasks.register<SpecStatusTask>("specStatusCheck") {
            description = "Fails when docs/dev/status.md is stale or the implemented-fixture count decreased (a ratchet)."
            group = "verification"
            spec.set(layout.projectDirectory.file("docs/spec/revokt-spec.md"))
            testRoots.from(subprojects.map { it.layout.projectDirectory.dir("src") })
            committed.set(layout.projectDirectory.file("docs/dev/status.md"))
            ctSeedGap.set(layout.projectDirectory.file("revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/ct-seed-gap.tsv"))
            checkOnly.set(true)
            rootDir.set(layout.projectDirectory)
        }
        val verifyHeaders = tasks.register<VerifyHeaderLocationsTask>("verifyHeaderLocations") {
            description = "MPL-2.0 headers only under revokt-clubcard/src/*/kotlin/**/port/** (spec §3.1 item 3)."
            group = "verification"
            rootDir.set(layout.projectDirectory)
            sources.from(
                layout.projectDirectory.asFileTree.matching {
                    include("**/*.kt", "**/*.kts", "**/*.java", "**/*.rs", "**/*.go", "**/*.py")
                    exclude("build/**", "*/build/**", "build-logic/*/build/**", "consumers/*/build/**", ".gradle/**", "**/.gradle/**", ".git/**", "**/node_modules/**", "LICENSES/**", "**/target/**")
                },
            )
        }
        val verifyCorpus = tasks.register<VerifyCorpusManifestTask>("verifyCorpusManifest") {
            description = "corpus/ matches corpus/manifest.sha256; build/corpus too when -Prevokt.corpus points at it."
            group = "verification"
            corpusDir.set(layout.projectDirectory.dir("corpus"))
            manifest.set(layout.projectDirectory.file("corpus/manifest.sha256"))
            externalCorpus.set(providers.gradleProperty("revokt.corpus").map { layout.projectDirectory.dir(it) })
            corpusPin.set(layout.projectDirectory.file("gradle/corpus-pin.properties"))
            rootDir.set(layout.projectDirectory)
        }
        val verifyMatrix = tasks.register<VerifyOracleMatrixTask>("verifyOracleMatrix") {
            description = "CI and the nightly run the §9.2 version matrix of gradle/oracle-matrix.properties."
            group = "verification"
            matrix.set(layout.projectDirectory.file("gradle/oracle-matrix.properties"))
            ci.set(layout.projectDirectory.file(".github/workflows/ci.yml"))
            nightly.set(layout.projectDirectory.file(".github/workflows/nightly.yml"))
            catalog.set(layout.projectDirectory.file("gradle/libs.versions.toml"))
        }
        tasks.register<WriteCorpusManifestTask>("writeCorpusManifest") {
            description = "Regenerates corpus/manifest.sha256; only in a PR that admits corpus entries (docs/dev/corpus.md)."
            group = "revokt"
            corpusDir.set(layout.projectDirectory.dir("corpus"))
            manifest.set(layout.projectDirectory.file("corpus/manifest.sha256"))
        }
        val resolveAll = tasks.register("resolveAndLockAll") {
            description = "Resolves every resolvable configuration in every project so --write-locks captures the gated ones too (CONTRIBUTING §3)."
            group = "revokt"
            notCompatibleWithConfigurationCache("resolves configurations from task actions; run with --no-configuration-cache")
        }

        // The base to compare the Rule fixture with: -Prevokt.growabilityBase (CI), else the merge base with origin/main.
        val explicitBase = providers.gradleProperty("revokt.growabilityBase")
        val mergeBase =
            providers.exec {
                commandLine("git", "merge-base", "HEAD", "origin/main")
                isIgnoreExitValue = true
            }.standardOutput.asText.map { it.trim() }
        val baseRef = explicitBase.orElse(mergeBase.map { it.ifEmpty { "origin/main" } })
        val verifyGrowability = tasks.register<VerifyRuleGrowabilityTask>("verifyRuleGrowability") {
            description = "The Rule golden fixture changed only as the growability contract permits (spec §4, #73)."
            group = "verification"
            fixture.set(layout.projectDirectory.file(RULE_FIXTURE))
            this.baseRef.set(baseRef)
            required.set(explicitBase.isPresent)
            projectVersion.set(providers.gradleProperty("revokt.version").orElse("0.1.0-SNAPSHOT"))
            baseCommitExists.set(
                baseRef.flatMap { ref ->
                    providers.exec {
                        commandLine("git", "cat-file", "-e", "$ref^{commit}")
                        isIgnoreExitValue = true
                    }.result.map { it.exitValue == 0 }
                },
            )
            baseFixture.set(
                baseRef.flatMap { ref ->
                    val show =
                        providers.exec {
                            commandLine("git", "show", "$ref:$RULE_FIXTURE")
                            isIgnoreExitValue = true
                        }
                    show.result.zip(show.standardOutput.asText) { r, text -> text.takeIf { r.exitValue == 0 } }
                },
            )
        }

        // `base` registers the root `check` lifecycle task that the gates hang off.
        tasks.named("check") {
            dependsOn(specStatusCheck, verifyHeaders, verifyCorpus, verifyMatrix, verifyGrowability)
            // build-logic is an included build; its own tests (TestKit, the detekt rules) are part of the gate.
            dependsOn(gradle.includedBuild("build-logic").task(":convention:check"))
            dependsOn(gradle.includedBuild("build-logic").task(":revokt-detekt-rules:check"))
        }
        specStatus.configure { mustRunAfter(specStatusCheck) }

        // -Prevokt.ci: the consumer builds (and, through the kmp plugin's purity flag, the linuxX64 compile).
        if (Conventions.flag(this, "revokt.ci")) {
            registerConsumerBuilds()
        }

        allprojects {
            group = Conventions.GROUP
            version = rootProject.providers.gradleProperty("revokt.version").getOrElse("0.1.0-SNAPSHOT")
            val perProject = tasks.register<ResolveAndLockAllTask>("resolveAndLockAllProject") {
                group = "revokt"
                notCompatibleWithConfigurationCache("resolves configurations from a task action")
            }
            resolveAll.configure { dependsOn(perProject) }
        }
    }
}
