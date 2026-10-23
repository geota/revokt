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

    private fun entries(): List<File> =
        checkNotNull(corpus.listFiles { f -> f.isDirectory }) {
            "$corpus is not a directory"
        }.sortedBy { it.name }

    private fun filtersIn(entry: File): List<File> =
        checkNotNull(
            entry.listFiles { f ->
                f.isFile && f.name.contains(".filter")
            },
        ) { "$entry is not a directory" }.sortedBy {
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
                    val mismatches =
                        goldens.mapNotNull { line ->
                            // Four columns; detekt caps destructuring at three, so index them.
                            val fields = line.split('\t')
                            val actual = query(filter, issuer = fields[0], serial = fields[1], scts = fields[2])
                            if (actual.goldenName == fields[3]) null else "$line -> $actual"
                        }
                    assertTrue(
                        mismatches.isEmpty(),
                        "${mismatches.size} of ${goldens.size} goldens disagree; first: ${mismatches.firstOrNull()}",
                    )
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
        assertEquals(a.universe.logs, b.universe.logs, name)
        assertEquals(a.index, b.index, name)
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
        val key = CrliteKey(IssuerSpkiHash(issuer.decodeHex()), serial.decodeHex())
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
