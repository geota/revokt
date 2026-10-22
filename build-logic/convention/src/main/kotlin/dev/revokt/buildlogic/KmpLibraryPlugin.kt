// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jlleitschuh.gradle.ktlint.KtlintExtension

/**
 * A published Kotlin multiplatform library: jvm always, linuxX64 under `-Prevokt.purityGate` (compile only),
 * explicit API, JDK 11 bytecode built on 21, ktlint, detekt (with the repository rules and the commonMain
 * purity check), Kover, API dumps, the POM licence and dependency-scope assertions, dependency locking.
 */
class KmpLibraryPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        pluginManager.apply("org.jetbrains.kotlin.multiplatform")
        pluginManager.apply("maven-publish")
        pluginManager.apply("org.jlleitschuh.gradle.ktlint")
        pluginManager.apply("io.gitlab.arturbosch.detekt")
        pluginManager.apply("org.jetbrains.kotlinx.kover")

        applyDependencyLocking()

        extensions.configure<KotlinMultiplatformExtension> {
            explicitApi()
            jvmToolchain(Conventions.JDK_BUILD)
            jvm {
                compilerOptions {
                    jvmTarget.set(JvmTarget.JVM_11)
                    freeCompilerArgs.add("-Xjdk-release=${Conventions.JDK_RELEASE}")
                }
                testRuns.configureEach {
                    executionTask.configure { useJUnitPlatform() }
                }
            }
            if (Conventions.flag(project, "revokt.purityGate")) {
                // The authoritative commonMain purity gate: it must compile with no JVM in sight (spec §3).
                linuxX64()
            }
            compilerOptions {
                allWarningsAsErrors.set(true)
            }
        }

        if (Conventions.flag(project, "revokt.purityGate")) {
            // Compile only: never link or run a native test binary (CONTRIBUTING §3).
            tasks.matching {
                it.name == "linuxX64Test" || it.name.startsWith("linkDebugTestLinuxX64") || it.name == "compileTestKotlinLinuxX64" ||
                    it.name == "linuxX64SourcesJar" || (it.name.startsWith("publish") && it.name.contains("LinuxX64"))
            }.configureEach { enabled = false }   // the native target is a purity gate, never a published artifact
        }

        extensions.configure<KtlintExtension> {
            version.set(VersionCatalog.ktlint(project))
            android.set(false)
            ignoreFailures.set(false)
        }

        extensions.configure<DetektExtension> {
            buildUponDefaultConfig = true
            allRules = false
            config.setFrom(rootProject.layout.projectDirectory.file("detekt.yml"))
            baseline = null
        }
        dependencies {
            "detektPlugins"(Conventions.DETEKT_RULES)
        }

        // detekt's KMP per-source-set tasks are unreliable for commonMain; register an explicit one (CONTRIBUTING §3).
        val detektCommonMain = tasks.register<Detekt>("detektCommonMain") {
            description = "Fast commonMain purity check (ForbiddenImport over java.*); the linuxX64 compile is the authoritative gate."
            group = "verification"
            source(layout.projectDirectory.dir("src/commonMain/kotlin"))
            config.setFrom(rootProject.layout.projectDirectory.file("detekt-common.yml"))
            buildUponDefaultConfig = false
            allRules = false
            ignoreFailures = false
            classpath.setFrom()
        }
        // Every per-source-set detekt task is a gate (the plain `detekt` task has no KMP sources); never the baseline/config generators.
        tasks.named("check") {
            dependsOn(detektCommonMain)
            dependsOn(tasks.withType<Detekt>().matching { !it.name.startsWith("detektBaseline") && it.name != "detektGenerateConfig" })
        }

        val verifyPomLicenses = tasks.register<VerifyPomLicensesTask>("verifyPomLicenses") {
            description = "Every generated POM declares exactly the module's licence (spec §3.1 item 1)."
            group = "verification"
            expectedLicense.set(Conventions.licenseOf(project.name))
            rootDir.set(rootProject.layout.projectDirectory)
            poms.from(layout.buildDirectory.dir("publications").map { dir -> dir.asFileTree.matching { include("**/pom-default.xml") } })
            dependsOn(tasks.matching { it.name.startsWith("generatePomFileFor") })
        }
        val verifyDependencyScopes = tasks.register<VerifyDependencyScopesTask>("verifyDependencyScopes") {
            description = "Okio and revokt-clubcard never in an api variant; bindings keep their client in their own module (spec §3)."
            group = "verification"
            projectName.set(project.name)
            apiDependencies.set(project.provider { declaredDependencies(project, "apiElements", "jvmApiElements") })
            runtimeDependencies.set(project.provider { declaredDependencies(project, "runtimeElements", "jvmRuntimeElements") })
        }
        tasks.named("check") { dependsOn(verifyPomLicenses, verifyDependencyScopes) }

        configurePublishingPom()

        tasks.withType<Test>().configureEach {
            systemProperty("junit.jupiter.execution.parallel.enabled", "false")
            configureTestJdk(project, this)
        }
    }
}
