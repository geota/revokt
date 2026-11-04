// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VerifyOracleMatrixTaskTest {
    private val task = ProjectBuilder.builder().build().tasks.register("matrixProbe", VerifyOracleMatrixTask::class.java).get()

    private val matrix = "jdk=17,21,25,27\njdk.ea=28\nconscrypt=conscrypt,conscrypt-previous\nupki=v1.0.1\nupki-revocation=v1.0.0\nupki-revocation.commit=$COMMIT\n"

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
              # The pins live in gradle/oracle-matrix.properties.
              - run: |
                  pin() { sed -n "s/^${'$'}1=//p" gradle/oracle-matrix.properties | tail -n 1; }
                  upki=${'$'}(pin upki)
                  spec=${'$'}(pin upki-revocation)
                  commit=${'$'}(pin upki-revocation.commit)
                  [ -n "${'$'}upki" ] || echo "::error::no upki pin in gradle/oracle-matrix.properties"
          android:
            steps:
              - run: echo v9.9.9
        """.trimIndent()

    private val nightly = "java-version: \"28-ea\"\n./gradlew -Prevokt.testJdk=28 -Porg.gradle.java.installations.fromEnv=JAVA_HOME_28_X64\njobs:\n" + upkiJob.prependIndent("  ") + "\n"

    private val upkiIndex = "# upki-index.bin: written by rustls/upki v1.0.1's `upki fetch` (record-upki-index.sh)\nfull-v3\tcorpus/x\tab\n"

    private val catalog = "[versions]\nconscrypt = \"2.8.0\"\nconscrypt-previous = \"2.7.0\"\n\n[libraries]\nx = { module = \"a:b\" }\n"

    @Test
    fun `the committed shape has no problem, and a JDK in another job is not read as the check matrix`() {
        assertEquals(emptyList(), task.problems(matrix, ci, nightly, catalog, upkiIndex))
    }

    @Test
    fun `a JDK drift between the matrix and ci yml is caught`() {
        val found = task.problems(matrix.replace("jdk=17,21,25,27", "jdk=17,21,25"), ci, nightly, catalog, upkiIndex)
        assertTrue(found.single().startsWith("ci.yml's check matrix runs JDKs"), "$found")
    }

    @Test
    fun `the nightly must replay the matrix's EA release`() {
        val found = task.problems(matrix.replace("jdk.ea=28", "jdk.ea=29"), ci, nightly, catalog, upkiIndex)
        assertEquals(3, found.size, "$found")
        assertTrue(task.problems(matrix, ci, nightly.replace("testJdk=28 ", "testJdk=280 "), catalog, upkiIndex).isNotEmpty())
    }

    @Test
    fun `the roll rule keeps 17 and an EA above the matrix`() {
        val dropped = matrix.replace("jdk=17,21,25,27", "jdk=21,25,27")
        val ci21 = ci.replace("- { jdk: \"17\", label: \"17\" }\n", "")
        assertTrue(task.problems(dropped, ci21, nightly, catalog, upkiIndex).any { "bytecode target" in it })
        assertTrue(task.problems(matrix.replace("jdk.ea=28", "jdk.ea=27"), ci, nightly.replace("28", "27"), catalog, upkiIndex).any { "not above" in it })
    }

    @Test
    fun `the Conscrypt keys are catalog versions and the ones the build wires`() {
        val third = matrix.replace("conscrypt=conscrypt,conscrypt-previous", "conscrypt=conscrypt,conscrypt-previous,conscrypt-old")
        val found = task.problems(third, ci, nightly, catalog, upkiIndex)
        assertTrue(found.any { "not gradle/libs.versions.toml versions" in it } && found.any { "the build wires" in it }, "$found")
    }

    @Test
    fun `the upki pins are vX_Y_Z tags and a 40-hex commit`() {
        val found = task.problems(matrix.replace("upki-revocation=v1.0.0\n", "").replace(COMMIT, COMMIT.take(7)), ci, nightly, catalog, upkiIndex)
        assertEquals(2, found.size, "$found")
        assertTrue(found.any { "upki-revocation pin '' is not a vX.Y.Z tag" in it } && found.any { "is not a 40-hex commit" in it }, "$found")
        val unprefixed = task.problems(matrix.replace("upki=v1.0.1\n", "upki=1.0.1\n"), ci, nightly, catalog, upkiIndex.replace("v1.0.1", "1.0.1"))
        assertTrue(unprefixed.single().startsWith("the matrix's upki pin '1.0.1' is not a vX.Y.Z tag"), "$unprefixed")
    }

    @Test
    fun `the upki index golden was recorded at the upki pin`() {
        val bumped = task.problems(matrix.replace("upki=v1.0.1", "upki=v1.0.2"), ci, nightly, catalog, upkiIndex)
        assertTrue(bumped.single().startsWith("upki-index.tsv records rustls/upki v1.0.1, the upki pin is 'v1.0.2': re-record"), "$bumped")
        val unrecorded = task.problems(matrix, ci, nightly, catalog, upkiIndex.lines().filterNot { "written by" in it }.joinToString("\n"))
        assertTrue(unrecorded.single().contains("(no provenance line)"), "$unrecorded")
    }

    @Test
    fun `the nightly's upki-release reads both pins from the matrix, and an action pin or another job's version is not a pin`() {
        assertTrue(task.problems(matrix, ci, nightly.replace("upki-release:", "upki-check:"), catalog, upkiIndex).single().startsWith("nightly.yml has no upki-release job"))
        val oneKey = task.problems(matrix, ci, nightly.replace("pin upki-revocation)", "pin upki-revocations)"), catalog, upkiIndex)
        assertTrue(oneKey.single().contains("does not read the upki-revocation pin"), "$oneKey")
        val noCommit = task.problems(matrix, ci, nightly.replace("pin upki-revocation.commit", "pin upki-revocation-commit"), catalog, upkiIndex)
        assertTrue(noCommit.single().contains("does not read the upki-revocation.commit pin"), "$noCommit")
        val literal = task.problems(matrix, ci, nightly.replace("upki=${'$'}(pin upki)", "upki=v1.0.1"), catalog, upkiIndex)
        assertTrue(literal.any { "does not read the upki pin" in it } && literal.any { "names [v1.0.1]" in it }, "$literal")
        // The comment and the ::error:: line still name the file; only the pin() definition counts.
        val elsewhere = task.problems(matrix, ci, nightly.replace("p\" gradle/oracle-matrix.properties", "p\" gradle/other.properties"), catalog, upkiIndex)
        assertTrue(elsewhere.single().contains("has no pin() that reads gradle/oracle-matrix.properties"), "$elsewhere")
    }

    private companion object {
        const val COMMIT = "7e6ded4bea8d845c5d269cd1bf1f182348962bbe"
    }
}
