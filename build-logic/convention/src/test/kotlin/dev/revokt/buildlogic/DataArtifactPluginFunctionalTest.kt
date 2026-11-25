// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testkit.runner.GradleRunner
import java.io.File
import java.nio.file.Files
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * TestKit (CONTRIBUTING §3; #145): `data-artifact` keeps its network tasks and the floor check's
 * `seedTimestamp<Channel>` out of `check` and publishes nothing to a Maven repository (0.2 seeds are GitHub release
 * assets), and [VerifySeedJarTask] holds the seed jar's layout: the manifest and the licence entry carrying the data
 * licence text, and the stored archive.
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

    @Test
    fun `check runs the fixture chain, never a network task, and nothing publishes`() =
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
            File(dir, "data/seed/build.gradle.kts").writeText("plugins { id(\"revokt.data-artifact\") }\n")
            val dry = runner(dir, ":revokt-seed:check", "--dry-run").build().output
            for (task in listOf("writeTestSeed", "writeDataLicense", "testSeedJar", "verifyTestSeedJar", "smokeLoadTestSeed")) {
                assertTrue(":revokt-seed:$task SKIPPED" in dry, "check does not run $task:\n$dry")
            }
            for (task in listOf("writeSeedCompat", "writeSeedDefault", "smokeLoadSeedCompat", "seedJarDefault", "seedTimestampCompat", "seedTimestampDefault")) {
                assertTrue(":revokt-seed:$task " !in dry, "check runs the network task $task:\n$dry")
            }
            val tasks = runner(dir, ":revokt-seed:tasks", "--all").build().output
            assertTrue("publish" !in tasks && "generatePomFile" !in tasks, "the seed project publishes:\n$tasks")
        }

    @Test
    fun `the seed jar holds exactly the manifest, the licence and the stored archive the job wrote`() =
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

            fun manifest(licence: String?) =
                Triple(
                    "META-INF/MANIFEST.MF",
                    ("Manifest-Version: 1.0\r\n" + (licence?.let { "${DataArtifacts.LICENSE_ATTRIBUTE}: $it\r\n" } ?: "") + "\r\n").toByteArray(),
                    false,
                )
            val good = manifest(DataArtifacts.LICENSE)
            val licence = Triple(DataArtifacts.LICENSE_ENTRY, (DataArtifacts.LICENSE + "\n").toByteArray(), false)
            val resource = Triple("revokt/seed-compat.zip", zip.readBytes(), true)
            assertEquals(emptyList(), VerifySeedJarTask.problems(jar("ok.jar", good, licence, resource), zip, "compat"))

            fun fails(
                jar: File,
                says: String,
                channel: String = "compat",
            ) {
                val found = VerifySeedJarTask.problems(jar, zip, channel)
                assertTrue(found.any { says in it }, "$found")
            }
            fails(jar("deflated.jar", good, licence, resource.copy(third = false)), "is deflated")
            fails(jar("class.jar", good, licence, resource, Triple("dev/revokt/X.class", ByteArray(4), false)), "entries [dev/revokt/X.class]")
            fails(jar("other.jar", good, licence, resource.copy(second = ByteArray(100))), "differs from seed.zip")
            fails(jar("none.jar", good, licence), "no revokt/seed-compat.zip")
            fails(jar("nomanifest.jar", licence, resource), "no META-INF/MANIFEST.MF")
            fails(jar("channel.jar", good, licence, resource), "no revokt/seed-default.zip", channel = "default")
            fails(jar("nolicence.jar", good, resource), "${DataArtifacts.LICENSE_ENTRY} is not the data licence text")
            fails(jar("apache.jar", good, licence.copy(second = "Apache-2.0".toByteArray()), resource), "is not the data licence text")
            fails(jar("unlabelled.jar", manifest(null), licence, resource), "is 'null', not the data licence text")
            fails(jar("mislabelled.jar", manifest("Apache-2.0"), licence, resource), "is 'Apache-2.0', not the data licence text")
        }
}
