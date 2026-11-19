// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * TestKit (CONTRIBUTING §3): the jvm-library convention wires its gates to `check`, and `verifyDependencyScopes` holds
 * spec §3 "Dependency scopes": revokt-engine is `api` in revokt-jsse.
 */
class JvmLibraryPluginFunctionalTest {
    /** A two-project build: a stand-in `revokt-engine` and a `revokt-jsse` on the jvm-library plugin. */
    private fun project(engineScope: String): File {
        val dir = Files.createTempDirectory("revokt-jvm").toFile()
        File(dir, "settings.gradle.kts").writeText(
            """
            dependencyResolutionManagement { repositories { mavenCentral() } }
            rootProject.name = "probe"
            include(":revokt-engine", ":revokt-jsse")
            """.trimIndent(),
        )
        File(dir, "detekt.yml").writeText("build:\n  maxIssues: 0\n")
        File(dir, "gradle.properties").writeText("org.gradle.java.installations.auto-download=false\n")
        File(dir, "revokt-engine").mkdirs()
        File(dir, "revokt-engine/build.gradle.kts").writeText(
            """
            plugins { `java-library` }
            group = "dev.revokt"
            // JDK 17 bytecode, as the real revokt-engine-jvm variant (the jvm-library side resolves for 17).
            tasks.withType<JavaCompile>().configureEach { options.release.set(17) }
            """.trimIndent(),
        )
        File(dir, "revokt-jsse").mkdirs()
        File(dir, "revokt-jsse/build.gradle.kts").writeText(
            """
            plugins { id("revokt.jvm-library") }
            group = "dev.revokt"
            dependencies { $engineScope(project(":revokt-engine")) }
            """.trimIndent(),
        )
        return dir
    }

    private fun runner(dir: File, vararg args: String): GradleRunner =
        GradleRunner.create().withProjectDir(dir).withPluginClasspath().withArguments(*args, "--offline", "--stacktrace")

    @Test
    fun `revokt-engine as api in revokt-jsse passes verifyDependencyScopes`() {
        val dir = project("api")
        try {
            val result = runner(dir, ":revokt-jsse:verifyDependencyScopes").build()
            assertEquals(TaskOutcome.SUCCESS, result.task(":revokt-jsse:verifyDependencyScopes")?.outcome, result.output)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `revokt-engine as implementation in revokt-jsse fails verifyDependencyScopes`() {
        val dir = project("implementation")
        try {
            val result = runner(dir, ":revokt-jsse:verifyDependencyScopes").buildAndFail()
            assertEquals(TaskOutcome.FAILED, result.task(":revokt-jsse:verifyDependencyScopes")?.outcome, result.output)
            assertTrue(result.output.contains("revokt-engine must be api in revokt-jsse"), result.output)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `jvm-library wires the type-resolved detekt tasks, animal-sniffer and the POM licence check to check`() {
        val dir = project("api")
        try {
            // The POM itself is generated and read by the real module's check (its lockfile resolves); here only the wiring.
            val result = runner(dir, ":revokt-jsse:check", "--dry-run").build()
            for (task in listOf("detektMain", "detektTest", "animalsnifferMain", "generatePomFileForMavenPublication", "verifyPomLicenses", "verifyDependencyScopes")) {
                assertTrue(result.output.contains(":revokt-jsse:$task SKIPPED"), "check does not run $task:\n${result.output}")
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
