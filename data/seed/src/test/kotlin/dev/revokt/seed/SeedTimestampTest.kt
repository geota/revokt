// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.seed

import dev.revokt.CrliteChannel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.engine.seed.SeedSignature
import dev.revokt.verify.JcaSignatureVerifier
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The floor check's re-verification (#308; `seedTimestamp<Channel>`), over the check path's test-signed jar
 * (`testSeedJar`, which the test task depends on) under the fixture's test pin: the signed `<ts>` of a jar whose content
 * signature verifies, and no `<ts>` for one that does not, with an earlier output deleted.
 */
class SeedTimestampTest {
    private val jar: Path = Path.of(checkNotNull(System.getProperty("revokt.testSeedJar")) { "run through Gradle" })
    private val pin: ByteArray = hex(Files.readString(Path.of(System.getProperty("revokt.testSeedPin"))).trim())
    private val pinned: MozillaRemoteSettings =
        MozillaRemoteSettings.DEFAULT
            .newBuilder()
            .pinnedRootSpkiSha256s(listOf(pin))
            .build()
    private val verifier = JcaSignatureVerifier()

    /** records.json's `last_modified`, read with `java.util.zip`, not the loader. */
    private val signedTs: Long =
        ZipFile(jar.toFile()).use { zip ->
            val archive = zip.getInputStream(zip.getEntry(RESOURCE)).readBytes()
            ZipInputStream(archive.inputStream()).use { z ->
                generateSequence { z.nextEntry }.first { it.name == "records.json" }
                Regex(""""last_modified":"(\d+)"""").find(z.readBytes().decodeToString())!!.groupValues[1].toLong()
            }
        }

    private fun withDir(block: (Path) -> Unit) {
        val dir = Files.createTempDirectory("seed-timestamp")
        try {
            block(dir)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    private fun verified(
        file: Path = jar,
        channel: CrliteChannel = CrliteChannel.COMPAT,
        source: MozillaRemoteSettings = pinned,
    ): SeedSignature = verifiedTimestamp(file, channel, source, verifier)

    private fun refused(
        result: SeedSignature,
        says: String,
    ) {
        val refused = assertIs<SeedSignature.Refused>(result)
        assertTrue(says in refused.detail, refused.detail)
    }

    /** A jar of [entries] (name to bytes), each stored, as `seedJar<Channel>` stores the archive. */
    private fun jarOf(
        path: Path,
        vararg entries: Pair<String, ByteArray>,
    ): Path {
        ZipOutputStream(Files.newOutputStream(path)).use { out ->
            for ((name, bytes) in entries) {
                val e = ZipEntry(name)
                e.method = ZipEntry.STORED
                e.size = bytes.size.toLong()
                e.crc = CRC32().apply { update(bytes) }.value
                out.putNextEntry(e)
                out.write(bytes)
                out.closeEntry()
            }
        }
        return path
    }

    private val archive: ByteArray = ZipFile(jar.toFile()).use { it.getInputStream(it.getEntry(RESOURCE)).readBytes() }

    @Test
    fun `the check path's jar verifies at its signed ts`() {
        assertEquals(signedTs, assertIs<SeedSignature.Verified>(verified()).timestampMillis)
    }

    @Test
    fun `the ts is written as one line, over an earlier output`() =
        withDir { dir ->
            val out = dir.resolve("revokt-seed-compat.ts").apply { writeText("1\n") }
            assertEquals(0, writeTimestamp(jar, CrliteChannel.COMPAT, pinned, verifier, out))
            assertEquals("$signedTs\n", out.readText())
            assertEquals(listOf(out), Files.list(dir).use { it.toList() }, "no temporary file is left")
        }

    @Test
    fun `a jar that does not verify writes nothing and deletes an earlier output`() =
        withDir { dir ->
            val out = dir.resolve("revokt-seed-compat.ts").apply { writeText("$signedTs\n") }
            assertEquals(1, writeTimestamp(jar, CrliteChannel.COMPAT, MozillaRemoteSettings.DEFAULT, verifier, out))
            assertFalse(out.exists(), "an earlier <ts> is left behind")
        }

    @Test
    fun `Mozilla's pins refuse the test-signed seed`() {
        refused(verified(source = MozillaRemoteSettings.DEFAULT), "the x5u chain fails")
    }

    @Test
    fun `a jar with no archive for the channel, or the other channel's archive under its name, is refused`() =
        withDir { dir ->
            refused(verified(channel = CrliteChannel.DEFAULT), "holds no revokt/seed-default.zip")
            val renamed = jarOf(dir.resolve("renamed.jar"), "revokt/seed-default.zip" to archive)
            refused(verified(renamed, CrliteChannel.DEFAULT), "the seed is for COMPAT, not DEFAULT")
        }

    @Test
    fun `a flipped byte in records json, the signature or the x5u chain is refused`() =
        withDir { dir ->
            for (name in listOf("records.json", "signature", "x5u.pem")) {
                // The local header's name, then its data: a flipped byte there fails the inflate, the CRC or the check.
                val at = String(archive, Charsets.ISO_8859_1).indexOf(name) + name.length + 8
                val flipped = archive.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }
                assertIs<SeedSignature.Refused>(verified(jarOf(dir.resolve("flipped-$name.jar"), RESOURCE to flipped)))
            }
        }

    @Test
    fun `a file that is not a jar, or no file, is refused`() =
        withDir { dir ->
            val text = dir.resolve("not.jar").apply { writeBytes("not a jar".toByteArray()) }
            refused(verified(text), "is not a jar")
            refused(verified(dir.resolve("absent.jar")), "absent.jar")
        }

    private companion object {
        const val RESOURCE = "revokt/seed-compat.zip"

        fun hex(text: String): ByteArray = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
