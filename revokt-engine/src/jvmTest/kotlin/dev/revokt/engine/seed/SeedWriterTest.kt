// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.FilterFormat
import dev.revokt.SyncFailure
import dev.revokt.engine.fetch.ChangesetVerification
import dev.revokt.engine.fetch.ChangesetVerifier
import dev.revokt.engine.fetch.ClientResult
import dev.revokt.engine.fetch.SignatureEntry
import dev.revokt.engine.fetch.client
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.response
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.update.UpdateFixtures
import dev.revokt.engine.verify.ContentSignature
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import java.nio.file.Files
import java.time.LocalDateTime
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import kotlin.io.path.deleteIfExists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §6.5 "Seed archive", the writer side (#145): [buildSeed]'s archive round-trips through the loader and through
 * `java.util.zip`, its bytes are fixed for fixed input, it refuses what the loader would refuse, and [SeedJob] fetches,
 * verifies and self-loads before it writes.
 */
internal class SeedWriterTest : SeedFixture() {
    private val now = ts + hour

    /** [server]'s whole collection, verified as the sync verifies it. */
    private fun verified(server: Server = Server()): ChangesetVerification.Verified {
        val c = client(server.fetcher, source)
        val changeset =
            assertIs<ClientResult.Ok<dev.revokt.engine.fetch.Changeset>>(
                c.fetchChangeset(server.ts, null),
            ).value
        val records = checkNotNull(ContentSignature.merge(emptyList(), changeset.changes))
        return assertIs<ChangesetVerification.Verified>(ChangesetVerifier(c, verifier, now).verify(changeset, records))
    }

    private fun bodies(vararg records: Rec): Map<String, ByteString> =
        records.associate {
            it.id to
                it.body.toByteString()
        }

    private fun build(
        v: ChangesetVerification.Verified = verified(),
        bodies: Map<String, ByteString> = bodies(full, delta),
        formats: Set<FilterFormat> = setOf(FilterFormat.V3, FilterFormat.V4),
    ): SeedBuild = buildSeed(v, CrliteChannel.COMPAT, bodies, formats, verifier)

    private fun built(build: SeedBuild = build()): SeedBuild.Built = assertIs<SeedBuild.Built>(build, "$build")

    private fun refused(
        build: SeedBuild,
        detail: String,
    ) {
        val refused = assertIs<SeedBuild.Refused>(build, "$build")
        assertTrue(detail in refused.detail, "'${refused.detail}' does not say '$detail'")
    }

    private fun loadBytes(bytes: ByteArray): SeedLoad = loader(Counted { bytes }.source).load(now)

    private fun job(server: Server = Server()): SeedJob =
        SeedJob(source, server.fetcher, verifier, CrliteChannel.COMPAT)

    @Test
    fun `the archive round-trips through the loader, its index byte-equal and seed json the first stored entry`() {
        val build = built()
        val load = installed(loadBytes(build.bytes))
        assertEquals("$ts/${delta.id}", load.generationId)
        assertEquals(build.generationId, load.generationId)
        assertEquals(ts, load.timestampMillis)
        // The test fixture's own index over the same records (#138), and the one the writer shipped.
        assertContentEquals(Seed().index(), build.index)
        assertEquals(FilterFormat.V3, build.filterFormat)
        val archive = checkNotNull(SeedArchive.open { Buffer().write(build.bytes) })
        assertEquals(SeedArchive.SEED_JSON, archive.entries.first().name)
        assertEquals(0, archive.entries.first().method, "seed.json is stored")
        assertTrue(archive.entries.drop(1).all { it.method == 8 }, "every other entry is deflated")
        var shipped: ByteArray? = null
        archive.read(listOf(checkNotNull(archive.entry(SeedArchive.INDEX)) to (1L shl 20))) { _, b -> shipped = b }
        assertContentEquals(build.index, shipped)
    }

    @Test
    fun `seed json is the compact header of the channel, the full's format and the signed ts`() {
        assertEquals(
            """{"seedFormat":1,"channel":"COMPAT","dataset":"CRLITE","filterFormat":"V3","recordsLastModified":$ts,"engineFloor":1}""",
            header(CrliteChannel.COMPAT, FilterFormat.V3, ts).decodeToString(),
        )
        val built = built().bytes
        val archive = checkNotNull(SeedArchive.open { Buffer().write(built) })
        var bytes: ByteArray? = null
        archive.read(listOf(archive.entries.first() to (1L shl 16))) { _, b -> bytes = b }
        assertContentEquals(header(CrliteChannel.COMPAT, FilterFormat.V3, ts), bytes)
    }

    @Test
    fun `java util zip reads every entry, in the spec's order, undated, with no extra field`() {
        val v = verified()
        val build = built(build(v))
        val file = Files.createTempFile("seed", ".zip")
        try {
            file.writeBytes(build.bytes)
            ZipFile(file.toFile()).use { zip ->
                val entries = zip.entries().toList()
                assertEquals(
                    listOf("seed.json", "records.json", "signature", "x5u.pem", "index.bin") +
                        listOf(full, delta).map { "attachments/${it.filename}" },
                    entries.map { it.name },
                )
                for (e in entries) {
                    assertEquals(if (e.name == "seed.json") ZipEntry.STORED else ZipEntry.DEFLATED, e.method, e.name)
                    assertEquals(LocalDateTime.of(1980, 2, 1, 0, 0), e.timeLocal, e.name)
                    assertNull(e.extra, e.name)
                    assertNull(e.comment, e.name)
                }
                val bodies = listOf(full, delta).associate { "attachments/${it.filename}" to it.body }
                for ((name, body) in bodies) {
                    assertContentEquals(
                        body,
                        zip.getInputStream(zip.getEntry(name)).readBytes(),
                    )
                }
                assertContentEquals(build.index, zip.getInputStream(zip.getEntry("index.bin")).readBytes())
                assertContentEquals(
                    ContentSignature.recordsJson(v.records, v.timestamp),
                    zip.getInputStream(zip.getEntry("records.json")).readBytes(),
                )
                assertEquals(
                    v.entry.signature,
                    zip.getInputStream(zip.getEntry("signature")).readBytes().decodeToString(),
                )
                assertContentEquals(v.x5uBody.toByteArray(), zip.getInputStream(zip.getEntry("x5u.pem")).readBytes())
            }
        } finally {
            file.deleteIfExists()
        }
    }

    @Test
    fun `fixed input gives fixed bytes`() {
        val v = verified()
        assertContentEquals(built(build(v)).bytes, built(build(v)).bytes)
        val server = Server()
        val first = assertIs<SeedJobResult.Built>(job(server).build(now))
        val second = assertIs<SeedJobResult.Built>(job(server).build(now))
        assertContentEquals(first.build.bytes, second.build.bytes)
    }

    @Test
    fun `an attachment filename over 32 characters is stored under the filename and mapped at load`() {
        val long = "20261017-1-compat-a-filename-over-thirty-two-characters.filter"
        assertTrue(long.length > 32)
        val named = Rec(full.id, false, full.effectiveTimestamp, long, full.body)
        val server = Server(records = listOf(named.json(), delta.json()))
        val build = built(build(verified(server), bodies(named, delta)))
        val archive = checkNotNull(SeedArchive.open { Buffer().write(build.bytes) })
        assertTrue(archive.entry("attachments/$long") != null, "${archive.entries}")
        installed(loadBytes(build.bytes))
    }

    @Test
    fun `a delta in another listed encoding than the full builds, with the full's filterFormat`() {
        val v4 = v4Delta()
        val mixed = Rec(delta.id, true, delta.effectiveTimestamp, delta.filename, v4, parent = full.id)
        val server = Server(records = listOf(full.json(), mixed.json()))
        val build = built(build(verified(server), bodies(full, mixed)))
        assertEquals(FilterFormat.V3, build.filterFormat)
        installed(loadBytes(build.bytes))
    }

    @Test
    fun `it refuses a body it was not given, an extra one, and one that differs from the signed record`() {
        refused(build(bodies = bodies(full)), "no body for ${delta.id}")
        refused(build(bodies = bodies(full, delta) + ("x" to "y".encodeUtf8())), "a body for x")
        refused(build(bodies = bodies(full) + (delta.id to full.body.toByteString())), "signed size")
        val flipped = delta.body.copyOf().also { it[0] = (it[0] + 1).toByte() }
        refused(build(bodies = bodies(full) + (delta.id to flipped.toByteString())), "SHA-256 differs")
    }

    @Test
    fun `it refuses records that fail the schema, place no generation, or declare a filter over the cap`() {
        val v = verified()

        fun with(records: List<String>) =
            ChangesetVerification.Verified(v.index, v.entry, records.map(::json), v.timestamp, v.x5uBody, v.path, null)
        refused(build(with(listOf("""{"id":"a","channel":7}"""))), "the schema")
        refused(build(with(listOf(delta.json()))), "place no generation")
        val big = Rec(full.id, false, full.effectiveTimestamp, full.filename, full.body, size = (256L shl 20))
        refused(build(with(listOf(big.json(), delta.json()))), "over MAX_FILTER_BYTES")
    }

    @Test
    fun `it refuses a filter that does not decode, and one in an encoding the engine does not list`() {
        val junk = ByteArray(64) { 7 }
        val bad = Rec(delta.id, true, delta.effectiveTimestamp, delta.filename, junk, parent = full.id)
        val server = Server(records = listOf(full.json(), bad.json()))
        refused(build(verified(server), bodies(full, bad)), "index.bin cannot be built")
        refused(build(formats = setOf(FilterFormat.V4)), "which the engine does not list")
    }

    @Test
    fun `it refuses a signature that does not verify over the records json it writes, and one over its cap`() {
        val v = verified()
        val other = Server().apply { ts = this@SeedWriterTest.ts + 1 }.sign()

        fun signed(signature: String?) =
            ChangesetVerification.Verified(
                v.index,
                SignatureEntry(signature, v.entry.x5u, v.entry.mode),
                v.records,
                v.timestamp,
                v.x5uBody,
                v.path,
                null,
            )
        refused(build(signed(other)), "does not verify over the records.json written")
        refused(build(signed(null)), "no signature")
        refused(build(signed("A".repeat(65 shl 10))), "over 64 KiB")
    }

    @Test
    fun `the job writes only after the self-load passes, through a temporary file`() {
        val dir = Files.createTempDirectory("seed-job")
        try {
            val out = dir.resolve("revokt-seed-compat.zip")
            val written = assertIs<SeedJobResult.Built>(job().write(now, "2026.10.21", out))
            assertEquals(out, written.path)
            assertContentEquals(written.build.bytes, out.readBytes())
            assertEquals(listOf(out), dir.listDirectoryEntries(), "no temporary file is left")
            installed(loadBytes(out.readBytes()))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a seed that verifies at the fetch but not at its signed ts fails the self-load and writes nothing`() {
        // The leaf is valid from the day after <ts>: the fetch checks it at now, a seed load at the signed <ts>.
        val later = chain(leaf = leaf(validity = window("20261022000000Z", "20500101000000Z")))
        val server = Server(pem = pem(later))
        val dir = Files.createTempDirectory("seed-job")
        try {
            val out = dir.resolve("revokt-seed-compat.zip")
            val failed = assertIs<SeedJobResult.Failed>(job(server).write(ts + 2 * day, "2026.10.23", out))
            assertTrue("the self-load fails" in failed.detail, failed.detail)
            assertEquals(emptyList(), dir.listDirectoryEntries())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a previous archive stays whole when a later run fails`() {
        val dir = Files.createTempDirectory("seed-job")
        try {
            val out = dir.resolve("revokt-seed-compat.zip")
            val previous = byteArrayOf(1, 2, 3)
            out.writeBytes(previous)
            val server = Server().apply { signature = Server().apply { ts = this@SeedWriterTest.ts + 1 }.sign() }
            val failed = assertIs<SeedJobResult.Failed>(job(server).write(now, "2026.10.21", out))
            assertEquals(SyncFailure.SIGNATURE_INVALID, failed.failure)
            assertContentEquals(previous, out.readBytes())
            assertEquals(listOf(out), dir.listDirectoryEntries())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `the version is checked before any fetch, and the signed ts must not be after its day`() {
        val dir = Files.createTempDirectory("seed-job")
        try {
            val out = dir.resolve("revokt-seed-compat.zip")
            for (bad in listOf("2026.13.01", "2026.02.30", "2026-10-21", "26.10.21", "2026.10.21.1", "")) {
                val server = Server()
                val failed = assertIs<SeedJobResult.Failed>(job(server).write(now, bad, out), bad)
                assertTrue("YYYY.MM.DD" in failed.detail, failed.detail)
                assertEquals(emptyList(), server.fetcher.requests, "nothing is fetched for '$bad'")
            }
            val early = assertIs<SeedJobResult.Failed>(job().write(now, "2026.10.20", out))
            assertTrue("after 2026.10.20 ends" in early.detail, early.detail)
            assertEquals(emptyList(), dir.listDirectoryEntries())
            assertIs<SeedJobResult.Built>(job().write(now, "2026.10.21", out))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `each fetch and verification failure ends the job with its code`() {
        fun failure(configure: Server.() -> Unit): SyncFailure? =
            assertIs<SeedJobResult.Failed>(job(Server().apply(configure)).build(now)).failure
        assertEquals(SyncFailure.CHANGESET_FETCH, failure { overrides[monitor] = { response(500) } })
        assertEquals(SyncFailure.CHANGESET_FETCH, failure { overrides[changesetUrl] = { response(503) } })
        assertEquals(
            SyncFailure.SIGNATURE_INVALID,
            failure {
                signature =
                    Server().apply { ts = this@SeedWriterTest.ts + 1 }.sign()
            },
        )
        assertEquals(SyncFailure.X5U_FETCH, failure { overrides[x5u] = { response(404) } })
        assertEquals(SyncFailure.ATTACHMENT_BASE, failure { overrides["$base/"] = { response(500) } })
        assertEquals(
            SyncFailure.ATTACHMENT_MISMATCH,
            failure { bodies = mapOf(full.location to full.body, delta.location to full.body.copyOf(delta.body.size)) },
        )
        assertEquals(SyncFailure.SCHEMA_REJECTED, failure { records = listOf("""{"id":"a","channel":7}""") })
        assertEquals(SyncFailure.INDEX_INCONSISTENT, failure { records = listOf(delta.json()) })
        assertEquals(SyncFailure.CHANGESET_FETCH, failure { overrides[changesetUrl] = { response(304, ByteArray(0)) } })
        // A writer refusal has no SyncFailure: a filter the engine cannot decode passes the hash and fails buildIndex.
        val junk = ByteArray(64) { 7 }
        val bad = Rec(delta.id, true, delta.effectiveTimestamp, delta.filename, junk, parent = full.id)
        val refused =
            assertIs<SeedJobResult.Failed>(
                job(
                    Server(
                        records = listOf(full.json(), bad.json()),
                        bodies =
                            mapOf(
                                full.location to full.body,
                                bad.location to junk,
                            ),
                    ),
                ).build(now),
            )
        assertNull(refused.failure)
        assertTrue("index.bin cannot be built" in refused.detail, refused.detail)
    }

    @Test
    fun `the zip writer refuses names it cannot write as the loader reads them`() {
        for (name in listOf("", "a b", "é", "a\u0000")) {
            assertIs<IllegalArgumentException>(
                runCatching {
                    SeedZip.write(listOf(SeedZipEntry(name, ByteArray(0))))
                }.exceptionOrNull(),
            )
        }
        assertIs<IllegalArgumentException>(
            runCatching {
                SeedZip.write(listOf(SeedZipEntry("a", ByteArray(0)), SeedZipEntry("a", ByteArray(0))))
            }.exceptionOrNull(),
        )
        val many = (0..SeedZip.MAX_ENTRIES).map { SeedZipEntry("e$it", ByteArray(0), stored = true) }
        assertIs<IllegalArgumentException>(runCatching { SeedZip.write(many) }.exceptionOrNull())
    }

    /** The committed V4 encoding of the fixture delta (corpus/clubcard, #90). */
    private fun v4Delta(): ByteArray =
        dev.revokt.ClubcardCorpus
            .file(UpdateFixtures.DELTA_PATH + ".v4")
            .readBytes()
}
