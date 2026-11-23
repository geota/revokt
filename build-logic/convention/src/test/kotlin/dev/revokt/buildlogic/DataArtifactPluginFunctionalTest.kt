// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import java.io.File
import java.nio.file.Files
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * TestKit (CONTRIBUTING §3; #145): `verifyPomLicenses` accepts the data licence text only for the data artifacts'
 * coordinates, read from each POM; `data-artifact` publishes POMs with no dependency and keeps its network tasks out of
 * `check`; [VerifySeedJarTask] holds the seed jar's layout.
 */
class DataArtifactPluginFunctionalTest {
    private fun runner(
        dir: File,
        vararg args: String,
    ): GradleRunner = GradleRunner.create().withProjectDir(dir).withPluginClasspath().withArguments(*args, "--offline", "--stacktrace")

    private fun withDir(block: (File) -> Unit) {
        val dir = Files.createTempDirectory("revokt-data").toFile()
        try {
            block(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    /** A POM as Gradle generates one: coordinates, then each of [licenses], then [extra]. */
    private fun pom(
        group: String,
        artifact: String,
        licenses: List<String>,
        extra: String = "",
    ): String =
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>$group</groupId>
          <artifactId>$artifact</artifactId>
          <version>1</version>
          <licenses>${licenses.joinToString("") { "<license><name>$it</name></license>" }}</licenses>
          $extra
        </project>
        """.trimIndent()

    /**
     * One build whose `check<n>` task runs [VerifyPomLicensesTask] over the n-th of [poms] with the code licence
     * `Apache-2.0`, as a code module's is configured.
     */
    private fun pomProject(
        dir: File,
        poms: List<String>,
        expected: String = "Apache-2.0",
    ) {
        File(dir, "settings.gradle.kts").writeText("rootProject.name = \"probe\"\n")
        poms.forEachIndexed { i, text -> File(dir, "poms/$i/pom-default.xml").apply { parentFile.mkdirs() }.writeText(text) }
        File(dir, "build.gradle.kts").writeText(
            """
            plugins { id("revokt.bom") }
            ${poms.indices.joinToString("\n") { i ->
                """
                tasks.register<dev.revokt.buildlogic.VerifyPomLicensesTask>("check$i") {
                    expectedLicense.set("$expected")
                    rootDir.set(layout.projectDirectory)
                    poms.from("poms/$i/pom-default.xml")
                }
                """
            }}
            """.trimIndent(),
        )
    }

    private fun outcome(
        dir: File,
        task: String,
        pass: Boolean,
        says: String? = null,
    ) {
        val result = if (pass) runner(dir, task).build() else runner(dir, task).buildAndFail()
        assertEquals(if (pass) TaskOutcome.SUCCESS else TaskOutcome.FAILED, result.task(":$task")?.outcome, result.output)
        if (says != null) assertTrue(says in result.output, result.output)
    }

    @Test
    fun `the data licence passes only on the data artifacts' exact coordinates`() =
        withDir { dir ->
            val data = DataArtifacts.LICENSE
            pomProject(
                dir,
                listOf(
                    pom("dev.revokt", "revokt-seed-compat", listOf(data)),
                    pom("dev.revokt", "revokt-seed-default", listOf(data)),
                    pom("dev.revokt", "revokt-engine", listOf(data)),
                    pom("dev.revokt", "revokt-seed-other", listOf(data)),
                    pom("dev.revokt.x", "revokt-seed-compat", listOf(data)),
                    pom("dev.revokt", "revokt-seed-compat", listOf("Apache-2.0")),
                    pom("dev.revokt", "revokt-seed-compat", listOf(data, data)),
                    pom("dev.revokt", "revokt-jsse", listOf("MIT")),
                    pom("dev.revokt", "revokt-jsse", listOf("Apache-2.0")),
                ),
            )
            outcome(dir, "check0", pass = true)
            outcome(dir, "check1", pass = true)
            outcome(dir, "check2", pass = false, says = "declares licences [$data], expected exactly [Apache-2.0]")
            outcome(dir, "check3", pass = false, says = "revokt-seed-other")
            outcome(dir, "check4", pass = false, says = "dev.revokt.x:revokt-seed-compat")
            outcome(dir, "check5", pass = false, says = "a data artifact) declares licences [Apache-2.0]")
            outcome(dir, "check6", pass = false, says = "a data artifact")
            outcome(dir, "check7", pass = false, says = "declares licences [MIT], expected exactly [Apache-2.0]")
            outcome(dir, "check8", pass = true)
        }

    @Test
    fun `a code module configured with the data text still fails, and a POM without coordinates fails`() =
        withDir { dir ->
            pomProject(dir, listOf(pom("dev.revokt", "revokt-engine", listOf(DataArtifacts.LICENSE))), expected = DataArtifacts.LICENSE)
            outcome(dir, "check0", pass = false, says = "is not a data artifact")
            val anonymous = Pom(null, "revokt-seed-compat", null, listOf(DataArtifacts.LICENSE), emptySet())
            assertTrue(VerifyPomLicensesTask.licenseProblem(anonymous, "Apache-2.0")!!.contains("no groupId"))
            val nameless = Pom("dev.revokt", null, null, listOf(DataArtifacts.LICENSE), emptySet())
            assertTrue(VerifyPomLicensesTask.licenseProblem(nameless, "Apache-2.0")!!.contains("no artifactId"))
        }

    @Test
    fun `the data-artifact plugin's POMs carry the data licence and no dependency, and check never reaches the network`() =
        withDir { dir ->
            File(dir, "settings.gradle.kts").writeText(
                """
                dependencyResolutionManagement { repositories { mavenCentral() } }
                rootProject.name = "probe"
                include(":revokt-engine", ":revokt-seed")
                project(":revokt-seed").projectDir = file("data/seed")
                """.trimIndent(),
            )
            File(dir, "detekt.yml").writeText("build:\n  maxIssues: 0\n")
            File(dir, "gradle.properties").writeText("org.gradle.java.installations.auto-download=false\n")
            File(dir, "revokt-engine").mkdirs()
            File(dir, "revokt-engine/build.gradle.kts").writeText("plugins { `java-library` }\ngroup = \"dev.revokt\"\n")
            File(dir, "data/seed").mkdirs()
            // The probe has no lockfile; the real project's is committed (data/seed/gradle.lockfile).
            File(dir, "data/seed/build.gradle.kts").writeText(
                """
                plugins { id("revokt.data-artifact") }
                dependencyLocking { lockMode.set(LockMode.LENIENT) }
                """.trimIndent(),
            )
            val result = runner(dir, ":revokt-seed:verifyPomLicenses", ":revokt-seed:verifyDataPom").build()
            assertEquals(TaskOutcome.SUCCESS, result.task(":revokt-seed:verifyPomLicenses")?.outcome, result.output)
            assertEquals(TaskOutcome.SUCCESS, result.task(":revokt-seed:verifyDataPom")?.outcome, result.output)
            for (channel in DataArtifacts.CHANNELS) {
                val suffix = channel.replaceFirstChar { it.uppercase() }
                val text = File(dir, "data/seed/build/publications/seed$suffix/pom-default.xml").readText()
                val pom = Pom.read(text.toByteArray())
                assertEquals(listOf(DataArtifacts.GROUP, DataArtifacts.artifactId(channel)), listOf(pom.groupId, pom.artifactId))
                assertEquals(listOf(DataArtifacts.LICENSE), pom.licenses)
                assertTrue("dependencies" !in pom.elements && "parent" !in pom.elements, text)
            }
            assertTrue(!File(dir, "data/seed/build/publications/seedCompat/module.json").exists(), "no Gradle module metadata")

            val dry = runner(dir, ":revokt-seed:check", "--dry-run").build().output
            for (task in listOf("writeTestSeed", "testSeedJar", "verifyTestSeedJar", "smokeLoadTestSeed", "verifyPomLicenses", "verifyDataPom")) {
                assertTrue(":revokt-seed:$task SKIPPED" in dry, "check does not run $task:\n$dry")
            }
            for (task in listOf("writeSeedCompat", "writeSeedDefault", "smokeLoadSeedCompat", "seedJarDefault")) {
                assertTrue(":revokt-seed:$task " !in dry, "check runs the network task $task:\n$dry")
            }
        }

    @Test
    fun `a data-artifact POM with a dependency or other coordinates fails verifyDataPom`() {
        val ok = Pom.read(pom("dev.revokt", "revokt-seed-compat", listOf(DataArtifacts.LICENSE)).toByteArray())
        assertEquals(null, VerifyDataPomTask.problem(ok))
        val dependency = "<dependencies><dependency><groupId>dev.revokt</groupId><artifactId>revokt-engine</artifactId></dependency></dependencies>"
        for (extra in listOf(dependency, "<dependencyManagement/>", "<parent/>", "<packaging>pom</packaging>")) {
            val bad = Pom.read(pom("dev.revokt", "revokt-seed-compat", listOf(DataArtifacts.LICENSE), extra).toByteArray())
            assertTrue(VerifyDataPomTask.problem(bad) != null, extra)
        }
        val code = Pom.read(pom("dev.revokt", "revokt-engine", listOf("Apache-2.0")).toByteArray())
        assertTrue(VerifyDataPomTask.problem(code)!!.contains("not a data artifact"))
    }

    @Test
    fun `a POM with a DOCTYPE is refused, so no entity is ever expanded`() {
        val xxe = "<?xml version=\"1.0\"?><!DOCTYPE p [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><project><groupId>&x;</groupId></project>"
        assertFailsWith<Exception> { Pom.read(xxe.toByteArray()) }
    }

    @Test
    fun `the seed jar holds exactly the manifest and the stored archive the job wrote`() =
        withDir { dir ->
            val zip = File(dir, "seed.zip").apply { writeBytes(ByteArray(100) { it.toByte() }) }
            fun jar(
                name: String,
                vararg entries: Triple<String, ByteArray, Boolean>,
            ): File =
                File(dir, name).also { f ->
                    ZipOutputStream(f.outputStream()).use { out ->
                        for ((entryName, bytes, stored) in entries) {
                            val e = ZipEntry(entryName)
                            if (stored) {
                                e.method = ZipEntry.STORED
                                e.size = bytes.size.toLong()
                                e.crc = CRC32().apply { update(bytes) }.value
                            }
                            out.putNextEntry(e)
                            out.write(bytes)
                            out.closeEntry()
                        }
                    }
                }
            val manifest = Triple("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n".toByteArray(), false)
            val resource = Triple("revokt/seed-compat.zip", zip.readBytes(), true)
            assertEquals(emptyList(), VerifySeedJarTask.problems(jar("ok.jar", manifest, resource), zip, "compat"))
            fun fails(
                jar: File,
                says: String,
                channel: String = "compat",
            ) {
                val found = VerifySeedJarTask.problems(jar, zip, channel)
                assertTrue(found.any { says in it }, "$found")
            }
            fails(jar("deflated.jar", manifest, resource.copy(third = false)), "is deflated")
            fails(jar("class.jar", manifest, resource, Triple("dev/revokt/X.class", ByteArray(4), false)), "entries [dev/revokt/X.class]")
            fails(jar("other.jar", manifest, resource.copy(second = ByteArray(100))), "differs from seed.zip")
            fails(jar("none.jar", manifest), "no revokt/seed-compat.zip")
            fails(jar("nomanifest.jar", resource), "no META-INF/MANIFEST.MF")
            fails(jar("channel.jar", manifest, resource), "no revokt/seed-default.zip", channel = "default")
        }
}
