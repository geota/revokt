// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VerifyOracleMatrixTaskTest {
    private val task = ProjectBuilder.builder().build().tasks.register("matrixProbe", VerifyOracleMatrixTask::class.java).get()

    private val matrix = "jdk=17,21,25,27\njdk.ea=28\nconscrypt=conscrypt,conscrypt-previous\nupki=v1.0.1\nupki-revocation=v1.0.0\n"

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

    private val upkiJob =
        """
          upki-release:
            steps:
              - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
              - run: |
                  pin() { sed -n "s/^${'$'}1=//p" gradle/oracle-matrix.properties; }
                  upki=${'$'}(pin upki)
                  spec=${'$'}(pin upki-revocation)
          android:
            steps:
              - run: echo v9.9.9
        """.trimIndent()

    private val nightly = "java-version: \"28-ea\"\n./gradlew -Prevokt.testJdk=28 -Porg.gradle.java.installations.fromEnv=JAVA_HOME_28_X64\njobs:\n" + upkiJob.prependIndent("  ") + "\n"

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

    @Test
    fun `the upki pins are vX_Y_Z tags`() {
        val found = task.problems(matrix.replace("upki=v1.0.1\n", "upki=1.0.1\n").replace("upki-revocation=v1.0.0\n", ""), ci, nightly, catalog)
        assertEquals(2, found.size, "$found")
        assertTrue(found.all { "is not a vX.Y.Z tag" in it }, "$found")
    }

    @Test
    fun `the nightly's upki-release reads both pins from the matrix, and an action pin or another job's version is not a pin`() {
        assertTrue(task.problems(matrix, ci, nightly.replace("upki-release:", "upki-check:"), catalog).single().startsWith("nightly.yml has no upki-release job"))
        val oneKey = task.problems(matrix, ci, nightly.replace("pin upki-revocation", "pin upki-revocations"), catalog)
        assertTrue(oneKey.single().contains("does not read the upki-revocation pin"), "$oneKey")
        val literal = task.problems(matrix, ci, nightly.replace("upki=${'$'}(pin upki)", "upki=v1.0.1"), catalog)
        assertTrue(literal.any { "does not read the upki pin" in it } && literal.any { "names [v1.0.1]" in it }, "$literal")
        val elsewhere = task.problems(matrix, ci, nightly.replace("gradle/oracle-matrix.properties", "pins.properties"), catalog)
        assertTrue(elsewhere.single().contains("does not read gradle/oracle-matrix.properties"), "$elsewhere")
    }
}
