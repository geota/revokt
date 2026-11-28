// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.testkit.runner.GradleRunner
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * TestKit (CONTRIBUTING §3; #145): `data-artifact` keeps its network tasks and the floor check's
 * `seedTimestamp<Channel>` out of `check` and publishes nothing to a Maven repository (0.2 seeds are GitHub release
 * assets), and [VerifySeedJarTask] holds the seed jar's layout: the manifest and the licence entry carrying the data
 * licence text, and the stored archive. The oldest-minor smoke load (`smokeLoadOldestSeed<Channel>`) falls back to the
 * same-commit one only while nothing is released, and otherwise resolves the named release from a repository (here a
 * local file repository standing in for Maven Central) under dependency verification, failing when it cannot.
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
            for (
                task in listOf(
                    "writeSeedCompat",
                    "writeSeedDefault",
                    "smokeLoadSeedCompat",
                    "seedJarDefault",
                    "seedTimestampCompat",
                    "seedTimestampDefault",
                    "checkOldestSupportedVersion",
                    "smokeLoadOldestSeedCompat",
                    "smokeLoadOldestSeedDefault",
                )
            ) {
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

    /**
     * A build with `revokt.oldestSupportedVersion=[oldest]` (none when null): `:revokt-jsse` is a local project with
     * the released module's coordinates, so a resolution that picked it would show; the repository holds
     * `dev.revokt:revokt-jsse:0.2.0` unless [published] is false, and the verification metadata lists its SHA-256s,
     * the jar's wrong when [jarChecksumRight] is false.
     */
    private fun oldestBuild(
        dir: File,
        oldest: String?,
        published: Boolean = true,
        jarChecksumRight: Boolean = true,
    ) {
        File(dir, "settings.gradle.kts").writeText(
            """
            dependencyResolutionManagement { repositories { maven { url = uri("repo") } } }
            rootProject.name = "probe"
            include(":revokt-engine", ":revokt-jsse", ":revokt-seed")
            project(":revokt-seed").projectDir = file("data/seed")
            """.trimIndent(),
        )
        File(dir, "detekt.yml").writeText("build:\n  maxIssues: 0\n")
        File(dir, "gradle.properties").writeText(
            "org.gradle.java.installations.auto-download=false\nkotlin.stdlib.default.dependency=false\n" +
                (oldest?.let { "${OldestSupported.PROPERTY}=$it\n" } ?: ""),
        )
        for (name in listOf("revokt-engine", "revokt-jsse")) {
            File(dir, "$name/build.gradle.kts").apply { parentFile.mkdirs() }.writeText(
                "plugins { `java-library` }\ngroup = \"dev.revokt\"\nversion = \"0.3.0-SNAPSHOT\"\n",
            )
        }
        File(dir, "data/seed/build.gradle.kts").apply { parentFile.mkdirs() }.writeText(
            """
            plugins { id("revokt.data-artifact") }
            // What the oldest-minor smoke load runs on, resolved after the guard.
            tasks.register("oldestClasspath") {
                dependsOn("checkOldestSupportedVersion")
                val classpath = tasks.named("smokeLoadOldestSeedCompat").map { (it as JavaExec).classpath }
                doLast { classpath.get().files.forEach { println("classpath: " + it.invariantSeparatorsPath) } }
            }
            """.trimIndent(),
        )
        File(dir, "data/seed/gradle.lockfile").writeText("dev.revokt:revokt-jsse:0.2.0=smokeOldestRuntimeClasspath\nempty=\n")
        val release = File(dir, "repo/dev/revokt/revokt-jsse/0.2.0").apply { mkdirs() }
        val pom =
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>dev.revokt</groupId>
              <artifactId>revokt-jsse</artifactId>
              <version>0.2.0</version>
            </project>
            """.trimIndent().toByteArray()
        val jar =
            ByteArrayOutputStream().also { bytes ->
                ZipOutputStream(bytes).use { out ->
                    out.putNextEntry(ZipEntry("dev/revokt/jsse/Released.class"))
                    out.write(ByteArray(8))
                    out.closeEntry()
                }
            }.toByteArray()
        if (published) {
            File(release, "revokt-jsse-0.2.0.pom").writeBytes(pom)
            File(release, "revokt-jsse-0.2.0.jar").writeBytes(jar)
        }
        fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val jarSha = if (jarChecksumRight) sha256(jar) else sha256(jar + 0)
        File(dir, "gradle/verification-metadata.xml").apply { parentFile.mkdirs() }.writeText(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
               <configuration>
                  <verify-metadata>true</verify-metadata>
                  <verify-signatures>false</verify-signatures>
               </configuration>
               <components>
                  <component group="dev.revokt" name="revokt-jsse" version="0.2.0">
                     <artifact name="revokt-jsse-0.2.0.jar"><sha256 value="$jarSha" origin="test"/></artifact>
                     <artifact name="revokt-jsse-0.2.0.pom"><sha256 value="${sha256(pom)}" origin="test"/></artifact>
                  </component>
               </components>
            </verification-metadata>
            """.trimIndent(),
        )
    }

    private fun newest(version: String) = "-P${OldestSupported.NEWEST_RELEASE_PROPERTY}=$version"

    @Test
    fun `with nothing released or named, the oldest-minor smoke load is the same-commit one`() =
        withDir { dir ->
            oldestBuild(dir, oldest = null)
            val checked = runner(dir, ":revokt-seed:checkOldestSupportedVersion", newest("")).build().output
            assertTrue("the oldest supported one is this commit's" in checked, checked)
            val dry = runner(dir, ":revokt-seed:smokeLoadOldestSeedCompat", newest(""), "--dry-run").build().output
            assertTrue(":revokt-seed:smokeLoadSeedCompat SKIPPED" in dry, "no fallback to the same-commit load:\n$dry")
            assertTrue(":revokt-seed:checkOldestSupportedVersion SKIPPED" in dry, dry)
            val tasks = runner(dir, ":revokt-seed:tasks", "--all").build().output
            assertFalse("SmokeOldest" in tasks, "a smokeOldest source set exists with nothing named:\n$tasks")
            // An empty value is unset too.
            File(dir, "gradle.properties").appendText("${OldestSupported.PROPERTY}=\n")
            runner(dir, ":revokt-seed:checkOldestSupportedVersion", newest("")).build()
        }

    @Test
    fun `a release that gradle_properties does not name fails before anything is fetched`() =
        withDir { dir ->
            oldestBuild(dir, oldest = null)
            val failed = runner(dir, ":revokt-seed:smokeLoadOldestSeedCompat", ":revokt-seed:smokeLoadSeedCompat", newest("0.2.0")).buildAndFail().output
            assertTrue("v0.2.0 is released, but ${OldestSupported.PROPERTY} in gradle.properties is empty" in failed, failed)
            assertFalse("Task :revokt-seed:writeSeedCompat" in failed, "the network write ran first:\n$failed")
            val unpassed = runner(dir, ":revokt-seed:checkOldestSupportedVersion").buildAndFail().output
            assertTrue("needs -P${OldestSupported.NEWEST_RELEASE_PROPERTY}" in unpassed, unpassed)
        }

    @Test
    fun `a named release is compiled and run against, from the repository, never the local project`() =
        withDir { dir ->
            oldestBuild(dir, oldest = "0.2.0")
            val dry = runner(dir, ":revokt-seed:smokeLoadOldestSeedCompat", newest("0.2.1"), "--dry-run").build().output
            for (task in listOf("checkOldestSupportedVersion", "compileSmokeOldestKotlin", "verifySeedJarCompat", "smokeLoadOldestSeedCompat")) {
                assertTrue(":revokt-seed:$task SKIPPED" in dry, "$task is not in the graph:\n$dry")
            }
            assertFalse(":revokt-seed:smokeLoadSeedCompat " in dry, "a named release fell back to the same-commit load:\n$dry")
            val out = runner(dir, ":revokt-seed:oldestClasspath", newest("0.2.1")).build().output
            val classpath = out.lines().filter { it.startsWith("classpath: ") }.map { it.removePrefix("classpath: ") }
            assertTrue(classpath.any { it.endsWith("/revokt-jsse-0.2.0.jar") }, "the release is not on the class path:\n$out")
            assertTrue(classpath.any { it.endsWith("/build/seed/revokt-seed-compat-unset.jar") }, "the seed jar is not on the class path:\n$out")
            assertFalse(classpath.any { "/revokt-jsse/build/" in it || "/revokt-engine/build/" in it }, "a local project is on the class path:\n$out")
            // check neither compiles nor lints the release's sources.
            val check = runner(dir, ":revokt-seed:check", "--dry-run").build().output
            assertFalse("compileSmokeOldestKotlin" in check || "detektSmokeOldest" in check, "check resolves the release:\n$check")
        }

    @Test
    fun `a named release that does not resolve or verify fails, never falls back`() {
        withDir { dir ->
            oldestBuild(dir, oldest = "0.2.0", published = false)
            val out = runner(dir, ":revokt-seed:oldestClasspath", newest("0.2.0")).buildAndFail().output
            assertTrue("Could not find dev.revokt:revokt-jsse:0.2.0" in out, out)
        }
        withDir { dir ->
            oldestBuild(dir, oldest = "0.2.0", jarChecksumRight = false)
            val out = runner(dir, ":revokt-seed:oldestClasspath", newest("0.2.0")).buildAndFail().output
            assertTrue("Dependency verification failed" in out && "revokt-jsse-0.2.0.jar" in out, out)
        }
    }

    @Test
    fun `a named release must agree with the newest tag`() {
        withDir { dir ->
            oldestBuild(dir, oldest = "0.2.0")
            val stale = runner(dir, ":revokt-seed:oldestClasspath", newest("0.3.0")).buildAndFail().output
            assertTrue("only the latest 0.x minor is supported" in stale, stale)
            assertFalse("classpath: " in stale, "the release resolved before the guard:\n$stale")
            val untagged = runner(dir, ":revokt-seed:oldestClasspath", newest("")).buildAndFail().output
            assertTrue("no vX.Y.Z tag exists" in untagged, untagged)
        }
        withDir { dir ->
            oldestBuild(dir, oldest = "0.2")
            val out = runner(dir, ":revokt-seed:tasks").buildAndFail().output
            assertTrue("${OldestSupported.PROPERTY}='0.2' in gradle.properties is not an X.Y.Z version" in out, out)
        }
    }
}
