// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.register
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension
import org.jlleitschuh.gradle.ktlint.KtlintExtension

/**
 * A published JVM-only library (revokt-jsse and the bindings, from 0.2): explicit API, JDK 17 bytecode on 21,
 * animal-sniffer against the API-26 signature (CONTRIBUTING §3), ktlint, detekt, Kover, API dumps, POM and scope
 * assertions, dependency locking. One `maven` publication of the java component with its sources jar, as the KMP
 * modules publish theirs, so `verifyPomLicenses` has a POM to read.
 */
class JvmLibraryPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        pluginManager.apply("org.jetbrains.kotlin.jvm")
        pluginManager.apply("java-library")
        pluginManager.apply("maven-publish")
        pluginManager.apply("org.jlleitschuh.gradle.ktlint")
        pluginManager.apply("io.gitlab.arturbosch.detekt")
        pluginManager.apply("org.jetbrains.kotlinx.kover")
        pluginManager.apply("ru.vyarus.animalsniffer")

        applyDependencyLocking()

        extensions.configure<KotlinJvmProjectExtension> {
            explicitApi()
            jvmToolchain(Conventions.JDK_BUILD)
            compilerOptions {
                jvmTarget.set(JvmTarget.fromTarget(Conventions.JDK_RELEASE.toString()))
                freeCompilerArgs.add("-Xjdk-release=${Conventions.JDK_RELEASE}")
                allWarningsAsErrors.set(true)
            }
        }

        extensions.configure<KtlintExtension> {
            version.set(VersionCatalog.ktlint(project))
            android.set(false)
        }
        extensions.configure<DetektExtension> {
            buildUponDefaultConfig = true
            config.setFrom(rootProject.layout.projectDirectory.file("detekt.yml"))
            baseline = null
        }
        // As in kmp-library: the type-resolved detektMain and detektTest are gates too, not only the plain `detekt`.
        tasks.named("check") {
            dependsOn(tasks.withType<Detekt>().matching { !it.name.startsWith("detektBaseline") && it.name != "detektGenerateConfig" })
        }
        dependencies {
            "detektPlugins"(Conventions.DETEKT_RULES)
            "signature"(VersionCatalog.gummyBears(project))
            constraints {
                add("ktlint", "ch.qos.logback:logback-core:1.5.34") { because("GHSA-jhq6-gfmj-v8fx, GHSA-p47f-322f-whfh, GHSA-qqpg-mvqg-649v") }
                add("ktlint", "ch.qos.logback:logback-classic:1.5.34") { because("keeps logback-classic aligned with logback-core") }
            }
        }

        extensions.configure<JavaPluginExtension> { withSourcesJar() }
        extensions.configure<PublishingExtension> {
            publications.register<MavenPublication>("maven") { from(components.getByName("java")) }
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
            description = "Okio and revokt-clubcard never in an api variant; revokt-engine api in revokt-jsse; bindings keep their client in their own module (spec §3)."
            group = "verification"
            projectName.set(project.name)
            apiDependencies.set(project.provider { declaredDependencies(project, "apiElements", "jvmApiElements") })
            runtimeDependencies.set(project.provider { declaredDependencies(project, "runtimeElements", "jvmRuntimeElements") })
        }
        tasks.named("check") { dependsOn(verifyPomLicenses, verifyDependencyScopes) }

        configurePublishingPom()

        tasks.withType<Test>().configureEach {
            useJUnitPlatform()
            configureTestJdk(project, this)
        }
    }
}
