// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.CrliteClubcard
import dev.revokt.clubcard.port.CrliteKey
import dev.revokt.clubcard.port.CrliteStatus
import dev.revokt.clubcard.port.IssuerSpkiHash
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.LogTimestamp
import dev.revokt.clubcard.port.Timestamp
import okio.ByteString.Companion.decodeHex
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The §9 end-to-end oracle in recorded form (docs/dev/corpus.md "Clubcard corpus"): every goldens line was produced
 * by `clubcard-crlite 0.6.2` through `revokt-oracle goldens`; revokt must agree on every line, zero tolerance.
 */
@OptIn(RevoktInternalApi::class)
class ClubcardCorpusReplayTest {
    private val corpus =
        File(System.getProperty("revokt.clubcardCorpus") ?: error("revokt.clubcardCorpus is set by the build"))

    private fun entries(): List<File> = corpus.listFiles { f -> f.isDirectory }!!.sortedBy { it.name }

    private fun filtersIn(entry: File): List<File> =
        entry.listFiles { f -> f.isFile && f.name.contains(".filter") }!!.sortedBy {
            it.name
        }

    @Test
    fun `corpus has the three recorded entries`() {
        assertEquals(listOf("compat-delta", "compat-full", "synthetic"), entries().map { it.name })
        for (entry in entries()) assertTrue(File(entry, "goldens.tsv").isFile, entry.name)
    }

    @TestFactory
    fun `corpus goldens replay with zero tolerance`(): List<DynamicTest> =
        entries().flatMap { entry ->
            val goldens = File(entry, "goldens.tsv").readLines().filter { it.isNotEmpty() && !it.startsWith("#") }
            filtersIn(entry).map { filterFile ->
                DynamicTest.dynamicTest("${entry.name}/${filterFile.name}: ${goldens.size} goldens") {
                    val filter = ClubcardFilters.decode(filterFile.readBytes())
                    var mismatches = 0
                    val first = StringBuilder()
                    for (line in goldens) {
                        val fields = line.split('\t')
                        val expected = fields[3]
                        val actual = query(filter, issuer = fields[0], serial = fields[1], scts = fields[2])
                        if (actual.goldenName != expected) {
                            mismatches++
                            if (first.isEmpty()) first.append("first mismatch: $line -> $actual")
                        }
                    }
                    assertEquals(0, mismatches, "$mismatches of ${goldens.size} goldens disagree; $first")
                }
            }
        }

    @Test
    fun `v3 and v4 encodings of the same filter decode to the same structure`() {
        for (entry in entries()) {
            val decoded = filtersIn(entry).map { ClubcardFilters.decode(it.readBytes()) }
            if (decoded.size < 2) continue
            val reference = decoded.first()
            for (other in decoded.drop(1)) assertSameStructure(reference, other, entry.name)
        }
    }

    private fun assertSameStructure(
        a: CrliteClubcard,
        b: CrliteClubcard,
        name: String,
    ) {
        assertEquals(a.universe.logs.keys, b.universe.logs.keys, name)
        for ((log, interval) in a.universe.logs) {
            val o = b.universe.logs.getValue(log)
            assertEquals(interval.low, o.low, name)
            assertEquals(interval.high, o.high, name)
        }
        assertEquals(a.index.keys, b.index.keys, name)
        for ((block, e) in a.index) {
            val o = b.index.getValue(block)
            assertEquals(e.toString(), o.toString(), name)
            assertEquals(e.exceptions, o.exceptions, name)
        }
        assertEquals(a.inner.approxFilter.size, b.inner.approxFilter.size, name)
        for (i in a.inner.approxFilter.indices) {
            assertContentEquals(
                a.inner.approxFilter[i],
                b.inner.approxFilter[i],
                name,
            )
        }
        assertContentEquals(a.inner.exactFilter, b.inner.exactFilter, name)
    }

    private fun query(
        filter: CrliteClubcard,
        issuer: String,
        serial: String,
        scts: String,
    ): CrliteStatus {
        val key = CrliteKey.of(IssuerSpkiHash(issuer.decodeHex()), serial.decodeHex())
        val timestamps =
            if (scts.isEmpty()) {
                emptyList()
            } else {
                scts.split(',').map { item ->
                    val (log, ts) = item.split(':')
                    LogTimestamp(LogId(log.decodeHex()), Timestamp(ts.toULong().toLong()))
                }
            }
        return filter.contains(key, timestamps)
    }

    /** The goldens' status names are upstream's; the port's enum names them in SCREAMING_CASE. */
    private val CrliteStatus.goldenName: String
        get() =
            when (this) {
                CrliteStatus.GOOD -> "Good"
                CrliteStatus.NOT_COVERED -> "NotCovered"
                CrliteStatus.NOT_ENROLLED -> "NotEnrolled"
                CrliteStatus.REVOKED -> "Revoked"
            }
}
