// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlatformExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.create
import org.gradle.kotlin.dsl.register

/** `revokt-bom`: code artifacts only, including both the KMP root and the `-jvm` artifact (spec §3). */
class BomPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("java-platform")
            pluginManager.apply("maven-publish")

            applyDependencyLocking()

            extensions.configure<JavaPlatformExtension> { allowDependencies() }

            val platformComponent = components.getByName("javaPlatform")
            extensions.configure<PublishingExtension> {
                publications.create<MavenPublication>("bom") {
                    from(platformComponent)
                }
            }
            configurePublishingPom()

            val verifyPomLicenses = tasks.register<VerifyPomLicensesTask>("verifyPomLicenses") {
                group = "verification"
                expectedLicense.set(Conventions.licenseOf(project.name))
                rootDir.set(rootProject.layout.projectDirectory)
                poms.from(layout.buildDirectory.dir("publications").map { dir -> dir.asFileTree.matching { include("**/pom-default.xml") } })
                dependsOn(tasks.matching { it.name.startsWith("generatePomFileFor") })
            }
            tasks.named("check") { dependsOn(verifyPomLicenses) }
        }
    }
}
