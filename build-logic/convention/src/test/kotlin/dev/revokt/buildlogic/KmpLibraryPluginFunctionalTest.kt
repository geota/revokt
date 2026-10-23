// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testkit.runner.GradleRunner
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue

/** TestKit (CONTRIBUTING §3): the kmp-library convention registers the gates and wires them to `check`. */
class KmpLibraryPluginFunctionalTest {
    private fun project(): File {
        val dir = Files.createTempDirectory("revokt-kmp").toFile()
        File(dir, "settings.gradle.kts").writeText(
            """
            dependencyResolutionManagement { repositories { mavenCentral() } }
            rootProject.name = "probe"
            """.trimIndent(),
        )
        File(dir, "detekt.yml").writeText("build:\n  maxIssues: 0\n")
        File(dir, "detekt-common.yml").writeText("build:\n  maxIssues: 0\n")
        File(dir, "build.gradle.kts").writeText(
            """
            plugins { id("revokt.kmp-library") }
            """.trimIndent(),
        )
        File(dir, "gradle.properties").writeText("org.gradle.java.installations.auto-download=false\n")
        File(dir, "src/commonMain/kotlin").mkdirs()
        return dir
    }

    @Test
    fun `kmp-library registers detektCommonMain, the POM and scope assertions and wires them to check`() {
        val dir = project()
        val result = GradleRunner.create()
            .withProjectDir(dir)
            .withPluginClasspath()
            .withArguments("tasks", "--all", "--offline", "-q")
            .build()
        val out = result.output
        for (task in listOf("detektCommonMain", "verifyPomLicenses", "verifyDependencyScopes", "ktlintCheck")) {   // apiCheck is the root plugin's
            assertTrue(out.contains(task), "missing task $task in:\n$out")
        }
        val dependencies = GradleRunner.create()
            .withProjectDir(dir)
            .withPluginClasspath()
            .withArguments("help", "--task", "check", "--offline", "-q")
            .build()
        assertTrue(dependencies.output.contains("check"), "check is not a task:\n${dependencies.output}")
    }
}
