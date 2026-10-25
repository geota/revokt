// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.Project
import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaToolchainService
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.withType

/** Facts every convention plugin shares. Changing one of these is a `spec` or `build` PR, never a drive-by. */
object Conventions {
    const val GROUP = "dev.revokt"
    const val JDK_BUILD = 21
    const val JDK_RELEASE = 17
    const val MARKER_INTERNAL = "dev.revokt.RevoktInternalApi"
    const val MARKER_TESTING = "dev.revokt.RevoktTestingApi"
    const val MARKER_CLUBCARD_INTERNAL = "dev.revokt.clubcard.RevoktInternalApi"
    const val DETEKT_RULES = "dev.revokt.build:revokt-detekt-rules"

    /** CONTRIBUTING §3 "Licensing": Apache-2.0 everywhere except the MPL port. */
    fun licenseOf(projectName: String): String = if (projectName == "revokt-clubcard") "MPL-2.0" else "Apache-2.0"

    fun licenseUrl(spdx: String): String = when (spdx) {
        "MPL-2.0" -> "https://www.mozilla.org/en-US/MPL/2.0/"
        else -> "https://www.apache.org/licenses/LICENSE-2.0"
    }

    fun flag(project: Project, name: String): Boolean =
        project.providers.gradleProperty(name).isPresent ||
            (name == "revokt.purityGate" && project.providers.gradleProperty("revokt.ci").isPresent)
}

/** `lockMode = STRICT`, every configuration (CONTRIBUTING §3 "Dependencies"). */
internal fun Project.applyDependencyLocking() {
    dependencyLocking {
        lockAllConfigurations()
        lockMode.set(LockMode.STRICT)
    }
}

/** POM metadata shared by every published module; the licence is asserted by [VerifyPomLicensesTask]. */
internal fun Project.configurePublishingPom() {
    val spdx = Conventions.licenseOf(name)
    extensions.configure<PublishingExtension> {
        publications.withType<MavenPublication>().configureEach {
            pom {
                name.set(project.name)
                description.set("revokt, a Kotlin TLS revocation library, is not affiliated with Revokt (revokt.com). Module ${project.name}.")
                url.set("https://revokt.dev")
                licenses {
                    license {
                        this.name.set(spdx)
                        this.url.set(Conventions.licenseUrl(spdx))
                    }
                }
                scm {
                    url.set("https://github.com/geota/revokt")
                    connection.set("scm:git:https://github.com/geota/revokt.git")
                }
                developers {
                    developer {
                        id.set("geota")
                        name.set("Adrian Maceiras")
                    }
                }
            }
        }
    }
}

/** `group:name` of every dependency declared on the named outgoing configurations (read at configuration time). */
internal fun declaredDependencies(project: Project, vararg configurationNames: String): Set<String> =
    configurationNames.mapNotNull { project.configurations.findByName(it) }
        .flatMap { it.allDependencies }
        .map { "${it.group}:${it.name}" }
        .toSet()

/**
 * CI matrix (CONTRIBUTING §6): the build always runs on JDK 21; `-Prevokt.testJdk=<n>` runs the tests on another
 * installed JDK (detected through `org.gradle.java.installations.fromEnv` in CI, never auto-downloaded).
 */
internal fun configureTestJdk(project: Project, test: Test) {
    val requested = project.providers.gradleProperty("revokt.testJdk").map { it.toInt() }.getOrElse(Conventions.JDK_BUILD)
    val toolchains = project.extensions.getByType<JavaToolchainService>()
    test.javaLauncher.set(toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(requested)) })
}
