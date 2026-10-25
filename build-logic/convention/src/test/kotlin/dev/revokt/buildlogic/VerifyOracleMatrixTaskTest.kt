// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VerifyOracleMatrixTaskTest {
    private val task = ProjectBuilder.builder().build().tasks.register("matrixProbe", VerifyOracleMatrixTask::class.java).get()

    private val matrix = "jdk=17,21,25,27\njdk.ea=28\nconscrypt=conscrypt,conscrypt-previous\n"

    private val ci =
        """
        jobs:
          check:
            strategy:
              matrix:
                include:
                  - { jdk: "17", label: "17" }
                  - { jdk: "21", label: "21" }
                  - { jdk: "25", label: "lts" }
                  - { jdk: "27", label: "feature" }
          other:
            steps:
              - { jdk: "11" }
        """.trimIndent()

    private val nightly = "java-version: \"28-ea\"\n./gradlew -Prevokt.testJdk=28 -Porg.gradle.java.installations.fromEnv=JAVA_HOME_28_X64\n"

    private val catalog = "[versions]\nconscrypt = \"2.8.0\"\nconscrypt-previous = \"2.7.0\"\n\n[libraries]\nx = { module = \"a:b\" }\n"

    @Test
    fun `the committed shape has no problem, and a JDK in another job is not read as the check matrix`() {
        assertEquals(emptyList(), task.problems(matrix, ci, nightly, catalog))
    }

    @Test
    fun `a JDK drift between the matrix and ci yml is caught`() {
        val found = task.problems(matrix.replace("jdk=17,21,25,27", "jdk=17,21,25"), ci, nightly, catalog)
        assertTrue(found.single().startsWith("ci.yml's check matrix runs JDKs"), "$found")
    }

    @Test
    fun `the nightly must replay the matrix's EA release`() {
        val found = task.problems(matrix.replace("jdk.ea=28", "jdk.ea=29"), ci, nightly, catalog)
        assertEquals(3, found.size, "$found")
        assertTrue(task.problems(matrix, ci, nightly.replace("testJdk=28 ", "testJdk=280 "), catalog).isNotEmpty())
    }

    @Test
    fun `the roll rule keeps 17 and an EA above the matrix`() {
        val dropped = matrix.replace("jdk=17,21,25,27", "jdk=21,25,27")
        val ci21 = ci.replace("- { jdk: \"17\", label: \"17\" }\n", "")
        assertTrue(task.problems(dropped, ci21, nightly, catalog).any { "bytecode target" in it })
        assertTrue(task.problems(matrix.replace("jdk.ea=28", "jdk.ea=27"), ci, nightly.replace("28", "27"), catalog).any { "not above" in it })
    }

    @Test
    fun `the Conscrypt keys are catalog versions and the ones the build wires`() {
        val third = matrix.replace("conscrypt=conscrypt,conscrypt-previous", "conscrypt=conscrypt,conscrypt-previous,conscrypt-old")
        val found = task.problems(third, ci, nightly, catalog)
        assertTrue(found.any { "not gradle/libs.versions.toml versions" in it } && found.any { "the build wires" in it }, "$found")
    }
}
