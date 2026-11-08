// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.ClubcardCorpus
import dev.revokt.CrliteQueryResult
import dev.revokt.FilterFormat
import dev.revokt.GenerationFiles
import dev.revokt.KotlinRevocationEngine
import dev.revokt.LogLevel
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.update.UpdateFixtures.Block
import dev.revokt.engine.update.UpdateFixtures.issuer
import dev.revokt.engine.update.UpdateFixtures.log
import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** The §6.5 engine self-check (#130): every input named, deterministic, first-match. */
@OptIn(RevoktInternalApi::class)
class SelfCheckTest {
    private val logger = UpdateFixtures.Recording()

    private fun run(
        files: GenerationFiles,
        answer: ((dev.revokt.CrliteQuery) -> CrliteQueryResult)? = null,
    ): SelfCheckResult {
        val index = C2spIndex.read(files.bytes("index.bin"))
        val filters = files.names.filter { it != "index.bin" }.associateWith { ClubcardFilters.decode(files.bytes(it)) }
        val query = answer ?: KotlinRevocationEngine().prepare(files)::query
        return SelfCheck.run(index, filters, query, logger)
    }

    private fun generation(vararg filters: ByteArray): GenerationFiles =
        ClubcardCorpus.generation("g", FilterFormat.V4, filters.withIndex().associate { (i, f) -> "f$i" to f })

    private fun probes(vararg filters: ByteArray): List<Probe> =
        assertIs<SelfCheckResult.Passed>(run(generation(*filters))).probes

    private fun bytes(vararg b: Int): ByteString = ByteArray(b.size) { b[it].toByte() }.toByteString()

    private val window = listOf(log(1) to (1_000L to 2_000L))

    @Test
    fun `the self-check passes on every corpus clubcard generation with the Kotlin engine`() {
        val corpus =
            listOf(
                listOf(UpdateFixtures.FULL_PATH) to ProbeKind.REVOKED_CANDIDATE_INVERTED,
                listOf(UpdateFixtures.FULL_PATH, UpdateFixtures.DELTA_PATH) to ProbeKind.REVOKED_CANDIDATE_INVERTED,
                listOf(UpdateFixtures.DELTA_PATH) to ProbeKind.REVOKED_CANDIDATE_MEMBER,
                listOf("compat-delta/20261021-1-compat.filter.delta.v4") to ProbeKind.REVOKED_CANDIDATE_MEMBER,
                listOf("synthetic/synthetic.v3.filter") to ProbeKind.REVOKED_CANDIDATE_INVERTED,
                listOf("synthetic/synthetic.v4.filter") to ProbeKind.REVOKED_CANDIDATE_INVERTED,
            )
        for ((paths, revoked) in corpus) {
            val files = ClubcardCorpus.generation("g", FilterFormat.V3, *paths.toTypedArray())
            val passed = assertIs<SelfCheckResult.Passed>(run(files), "$paths")
            val kinds = passed.probes.map { it.kind }
            assertEquals(
                List(paths.size) {
                    listOf(ProbeKind.ABSENT_INSIDE, ProbeKind.ABSENT_OUTSIDE)
                }.flatten() + revoked,
                kinds,
                "$paths",
            )
        }
        assertEquals(emptyList(), logger.messages)
    }

    @Test
    fun `a constant-answer engine fails it`() {
        val files = ClubcardCorpus.generation("g", FilterFormat.V3, UpdateFixtures.FULL_PATH, UpdateFixtures.DELTA_PATH)
        for (constant in listOf(
            CrliteQueryResult.NOT_REVOKED,
            CrliteQueryResult.REVOKED,
            CrliteQueryResult.ENGINE_ERROR,
        )) {
            val m = assertIs<SelfCheckResult.Mismatch>(run(files) { constant }, "$constant")
            assertEquals(ProbeKind.ABSENT_INSIDE, m.probe.kind)
            assertEquals(constant, m.actual)
        }
        for (constant in SelfCheck.NOT_ENROLLED_CLASS) {
            val m = assertIs<SelfCheckResult.Mismatch>(run(files) { constant }, "$constant")
            assertEquals(ProbeKind.REVOKED_CANDIDATE_INVERTED, m.probe.kind)
        }
        // An engine that answers the absent issuer correctly and NOT_REVOKED for everything else fails the REVOKED probe.
        val absent = SelfCheck.ABSENT_ISSUER_SEED
        val m =
            assertIs<SelfCheckResult.Mismatch>(
                run(files) { q ->
                    if (q.issuerSpkiHash.toByteString() ==
                        absent
                    ) {
                        CrliteQueryResult.NOT_ENROLLED
                    } else {
                        CrliteQueryResult.NOT_REVOKED
                    }
                },
            )
        assertEquals(setOf(CrliteQueryResult.REVOKED), m.probe.expected)
    }

    @Test
    fun `the absent issuer and the inside and outside SCTs are the named inputs`() {
        val probes =
            assertIs<SelfCheckResult.Passed>(
                run(ClubcardCorpus.generation("g", FilterFormat.V3, "synthetic/synthetic.v3.filter")),
            ).probes
        val (inside, outside) = probes
        assertContentEquals(SelfCheck.ABSENT_ISSUER_SEED.toByteArray(), inside.query.issuerSpkiHash)
        val sha256 =
            java.security.MessageDigest
                .getInstance(
                    "SHA-256",
                ).digest("revokt-self-check".toByteArray(Charsets.US_ASCII))
        assertContentEquals(sha256, SelfCheck.ABSENT_ISSUER_SEED.toByteArray())
        assertContentEquals(byteArrayOf(1), inside.query.serial)
        // The synthetic filter covers log [0;32] over [1000, 2000] and log [1;32] over everything; the first log in
        // index.bin order is [0;32].
        val sct = inside.query.scts.single()
        assertContentEquals(ByteArray(32), sct.logId)
        assertEquals(1_000, sct.timestampMillis)
        assertEquals(
            2_001,
            outside.query.scts
                .single()
                .timestampMillis,
        )
        assertEquals(SelfCheck.NOT_ENROLLED_CLASS, inside.expected)
        assertEquals(SelfCheck.NOT_ENROLLED_CLASS, outside.expected)
    }

    @Test
    fun `the outside probe is low - 1 when high is the maximum, and an empty window is no inside SCT`() {
        val max = -1L // u64::MAX
        val (inside, outside) = probes(UpdateFixtures.v4(listOf(log(1) to (10L to 5L), log(2) to (7L to max))))
        assertContentEquals(
            log(2).toByteArray(),
            inside.query.scts
                .single()
                .logId,
        )
        assertEquals(
            7,
            inside.query.scts
                .single()
                .timestampMillis,
        )
        assertEquals(
            6,
            outside.query.scts
                .single()
                .timestampMillis,
        )
        val wrapped = probes(UpdateFixtures.v4(listOf(log(1) to (0L to max))))[1]
        assertEquals(
            max,
            wrapped.query.scts
                .single()
                .timestampMillis,
        )
    }

    @Test
    fun `the absent issuer is incremented in its last byte until no filter's index holds it`() {
        val seed = SelfCheck.ABSENT_ISSUER_SEED.toByteArray()

        fun plus(k: Int) = seed.copyOf().also { it[31] = (it[31] + k).toByte() }.toByteString()
        val p =
            probes(UpdateFixtures.v4(window, listOf(Block(plus(0)))), UpdateFixtures.v4(window, listOf(Block(plus(1)))))
        assertContentEquals(plus(2).toByteArray(), p.first().query.issuerSpkiHash)
        val every = UpdateFixtures.v4(window, (0 until 256).map { Block(plus(it)) })
        logger.messages.clear()
        val skipped = probes(every)
        assertEquals(
            emptyList(),
            skipped.filter {
                it.kind == ProbeKind.ABSENT_INSIDE ||
                    it.kind == ProbeKind.ABSENT_OUTSIDE
            },
        )
        assertEquals(
            listOf(
                LogLevel.INFO to "engine self-check: every candidate issuer is enrolled, absent probes skipped",
                LogLevel.INFO to "engine self-check: no block yields a REVOKED probe, skipped",
            ),
            logger.messages,
        )
    }

    @Test
    fun `the candidates are 0x01 to 0x1000 as minimal DER INTEGER content, ascending`() {
        val c = SelfCheck.CANDIDATES
        assertEquals(4096, c.size)
        assertEquals(bytes(1), c[0])
        assertEquals(bytes(0x7F), c[0x7E])
        assertEquals(bytes(0, 0x80), c[0x7F])
        assertEquals(bytes(0, 0xFF), c[0xFE])
        assertEquals(bytes(1, 0), c[0xFF])
        assertEquals(bytes(0x10, 0), c.last())
    }

    @Test
    fun `REVOKED probe branch one - the first candidate revoked against an inverted block, serial first`() {
        // Issuer 1's inverted block revokes only its exception 0x02; issuer 2's (approxM == 0) revokes every serial.
        // Serial 0x01 comes first, so the probe is issuer 2's, not issuer 1's 0x02.
        val f =
            UpdateFixtures.v4(
                window,
                listOf(
                    Block(issuer(1), approxM = 8, exactM = 1, inverted = true, exceptions = listOf(bytes(2))),
                    Block(issuer(2), inverted = true),
                ),
            )
        val probe = probes(f).last()
        assertEquals(ProbeKind.REVOKED_CANDIDATE_INVERTED, probe.kind)
        assertContentEquals(issuer(2).toByteArray(), probe.query.issuerSpkiHash)
        assertContentEquals(byteArrayOf(1), probe.query.serial)
        assertEquals(
            1_000,
            probe.query.scts
                .single()
                .timestampMillis,
        )
        assertEquals(setOf(CrliteQueryResult.REVOKED), probe.expected)
        // Blocks by ascending issuer hash, filters in index.bin order.
        val two =
            UpdateFixtures.v4(
                window,
                listOf(Block(issuer(4), inverted = true), Block(issuer(3), inverted = true)),
            )
        val p = probes(UpdateFixtures.v4(window, listOf(Block(issuer(9), approxM = 8, exactM = 1))), two).last()
        assertEquals("f1", p.filter)
        assertContentEquals(issuer(3).toByteArray(), p.query.issuerSpkiHash)
    }

    @Test
    fun `REVOKED probe branch two - an inverted block's exception serial, when no candidate is revoked`() {
        val serial = bytes(0x20, 0, 0)
        val f =
            UpdateFixtures.v4(
                window,
                listOf(Block(issuer(1), approxM = 8, exactM = 1, inverted = true, exceptions = listOf(serial))),
            )
        val probe = probes(f).last()
        assertEquals(ProbeKind.REVOKED_EXCEPTION, probe.kind)
        assertContentEquals(serial.toByteArray(), probe.query.serial)
    }

    @Test
    fun `REVOKED probe branch three - the first candidate that is a member of a non-inverted block`() {
        val f =
            UpdateFixtures.v4(
                window,
                listOf(
                    Block(issuer(1)),
                    Block(issuer(2), approxM = 8, exactM = 1, inverted = true),
                    Block(issuer(3), approxM = 8, exactM = 1),
                ),
            )
        val probe = probes(f).last()
        assertEquals(ProbeKind.REVOKED_CANDIDATE_MEMBER, probe.kind)
        assertContentEquals(issuer(3).toByteArray(), probe.query.issuerSpkiHash)
        assertContentEquals(byteArrayOf(1), probe.query.serial)
    }

    @Test
    fun `no block that yields, or no coverage entry, skips the probe and logs it at INFO`() {
        val kinds = probes(UpdateFixtures.v4(window, listOf(Block(issuer(1))))).map { it.kind }
        assertEquals(listOf(ProbeKind.ABSENT_INSIDE, ProbeKind.ABSENT_OUTSIDE), kinds)
        assertEquals(
            listOf(LogLevel.INFO to "engine self-check: no block yields a REVOKED probe, skipped"),
            logger.messages,
        )
        logger.messages.clear()
        assertEquals(emptyList(), probes(UpdateFixtures.v4(emptyList(), listOf(Block(issuer(1), inverted = true)))))
        assertEquals(
            listOf(LogLevel.INFO to "engine self-check: no coverage entry, every probe skipped"),
            logger.messages,
        )
    }

    @Test
    fun `the first mismatch stops the check`() {
        val asked = mutableListOf<ProbeKind>()
        val files = generation(UpdateFixtures.v4(window, listOf(Block(issuer(2), inverted = true))))
        val probes = assertIs<SelfCheckResult.Passed>(run(files)).probes
        val m =
            assertIs<SelfCheckResult.Mismatch>(
                run(files) { q ->
                    asked += probes.first { it.query == q }.kind
                    CrliteQueryResult.NOT_REVOKED
                },
            )
        assertEquals(listOf(ProbeKind.ABSENT_INSIDE), asked)
        assertEquals("Mismatch(${m.probe} answered NOT_REVOKED)", m.toString())
    }
}
