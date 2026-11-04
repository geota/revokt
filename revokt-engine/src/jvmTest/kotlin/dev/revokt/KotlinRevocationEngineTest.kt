// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.port.CrliteKey
import dev.revokt.clubcard.port.CrliteStatus
import dev.revokt.clubcard.port.IssuerSpkiHash
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.LogTimestamp
import dev.revokt.clubcard.port.Timestamp
import okio.ByteString.Companion.decodeHex
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `KotlinRevocationEngine` (spec §3.2, §6, #90) over the committed `corpus/clubcard` generations. */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class KotlinRevocationEngineTest {
    private class Golden(
        val line: String,
        val query: CrliteQuery,
        val oracle: String,
    )

    /** `issuer \t serial \t log:ts[,…] \t Good|Revoked|NotCovered|NotEnrolled`, recorded by `clubcard-crlite 0.6.2`. */
    private fun goldens(entry: String): List<Golden> =
        ClubcardCorpus.file("$entry/goldens.tsv").readLines().filter { it.isNotEmpty() && !it.startsWith("#") }.map {
            val fields = it.split('\t')
            Golden(it, query(fields[0], fields[1], fields[2]), fields[3])
        }

    private fun query(
        issuer: String,
        serial: String,
        scts: String,
    ): CrliteQuery =
        CrliteQuery
            .Builder()
            .issuerSpkiHash(issuer.decodeHex().toByteArray())
            .serial(serial.decodeHex().toByteArray())
            .scts(
                scts.split(',').filter { it.isNotEmpty() }.map { sct ->
                    val (log, ts) = sct.split(':')
                    CrliteSct
                        .Builder()
                        .logId(log.decodeHex().toByteArray())
                        .timestampMillis(ts.toULong().toLong())
                        .build()
                },
            ).build()

    private val oracleResult =
        mapOf(
            "Good" to CrliteQueryResult.NOT_REVOKED,
            "Revoked" to CrliteQueryResult.REVOKED,
            "NotCovered" to CrliteQueryResult.NOT_COVERED,
            "NotEnrolled" to CrliteQueryResult.NOT_ENROLLED,
        )

    /** A single-filter generation answers as `clubcard-crlite` does, except that no SCTs is `NO_SCTS` (§3.2's class). */
    private fun expected(golden: Golden): CrliteQueryResult =
        if (golden.query.scts.isEmpty()) {
            assertEquals("NotCovered", golden.oracle, "an SCT-less query reaches no filter: ${golden.line}")
            CrliteQueryResult.NO_SCTS
        } else {
            oracleResult.getValue(golden.oracle)
        }

    private fun engineWith(generation: GenerationFiles): KotlinRevocationEngine =
        KotlinRevocationEngine().also { it.install(generation) }

    private val v3Full = "compat-full/20261017-1-compat.filter"
    private val v3Delta = "compat-delta/20261021-1-compat.filter.delta"
    private val v4Delta = "compat-delta/20261021-1-compat.filter.delta.v4"
    private val v3Synthetic = "synthetic/synthetic.v3.filter"
    private val v4Synthetic = "synthetic/synthetic.v4.filter"

    @TestFactory
    fun `a single-filter generation answers every recorded golden`(): List<DynamicTest> =
        listOf(
            Triple("compat-full", FilterFormat.V3, v3Full),
            Triple("compat-delta", FilterFormat.V3, v3Delta),
            Triple("compat-delta", FilterFormat.V4, v4Delta),
            Triple("synthetic", FilterFormat.V3, v3Synthetic),
            Triple("synthetic", FilterFormat.V4, v4Synthetic),
        ).map { (entry, format, path) ->
            DynamicTest.dynamicTest("$path as $format") {
                val engine = engineWith(ClubcardCorpus.generation("g", format, path))
                val goldens = goldens(entry)
                val mismatches =
                    goldens.mapNotNull { g ->
                        engine.query(g.query).takeIf { it != expected(g) }?.let { "${g.line} -> $it" }
                    }
                assertTrue(
                    mismatches.isEmpty(),
                    "${mismatches.size} of ${goldens.size}; first: ${mismatches.firstOrNull()}",
                )
            }
        }

    /** Each filter's own answer, from the port that the goldens test above checks against the oracle. */
    private fun perFilter(
        path: String,
        q: CrliteQuery,
    ): CrliteStatus =
        ClubcardFilters.decode(ClubcardCorpus.file(path).readBytes()).contains(
            CrliteKey(IssuerSpkiHash(q.issuerSpkiHash.decodeToKey()), q.serial.decodeToKey()),
            q.scts.map { LogTimestamp(LogId(it.logId.decodeToKey()), Timestamp(it.timestampMillis)) },
        )

    private fun ByteArray.decodeToKey() = okio.ByteString.of(*this)

    /** Spec §6.2's aggregate over per-filter answers, written out independently of the engine. */
    private fun aggregate(statuses: List<CrliteStatus>): CrliteQueryResult {
        val covering = statuses.filter { it != CrliteStatus.NOT_COVERED }
        return when {
            covering.isEmpty() -> CrliteQueryResult.NOT_COVERED
            CrliteStatus.REVOKED in covering -> CrliteQueryResult.REVOKED
            CrliteStatus.GOOD in covering -> CrliteQueryResult.NOT_REVOKED
            else -> CrliteQueryResult.NOT_ENROLLED
        }
    }

    @TestFactory
    fun `a full and a delta aggregate as spec 6_2 says`(): List<DynamicTest> =
        listOf(
            Triple(FilterFormat.V3, listOf(v3Full, v3Delta), listOf("compat-full", "compat-delta")),
            Triple(FilterFormat.V4, listOf(v4Synthetic, v4Delta), listOf("synthetic", "compat-delta")),
        ).map { (format, paths, entries) ->
            DynamicTest.dynamicTest("$paths") {
                val engine = engineWith(ClubcardCorpus.generation("g", format, *paths.toTypedArray()))
                val queries = entries.flatMap { goldens(it) }.map { it.query }.filter { it.scts.isNotEmpty() }
                val answers = queries.map { q -> engine.query(q) to aggregate(paths.map { perFilter(it, q) }) }
                val mismatches = queries.zip(answers).filter { (_, a) -> a.first != a.second }
                assertTrue(
                    mismatches.isEmpty(),
                    "${mismatches.size} of ${queries.size}; first: ${mismatches.firstOrNull()}",
                )
                val seen = answers.map { it.first }.toSet()
                assertTrue(
                    seen.containsAll(
                        listOf(CrliteQueryResult.REVOKED, CrliteQueryResult.NOT_REVOKED, CrliteQueryResult.NOT_COVERED),
                    ),
                    "the queries exercise the aggregate: $seen",
                )
            }
        }

    private val anyQuery: CrliteQuery by lazy { goldens("compat-full").first { it.oracle == "Revoked" }.query }

    @Test
    fun `precedence is closed, then no data, then no SCTs, then the aggregate`() {
        val engine = KotlinRevocationEngine()
        assertEquals(CrliteQueryResult.NO_DATA, engine.query(anyQuery))
        assertNull(engine.coverageEndMillis)
        engine.install(ClubcardCorpus.generation("g", FilterFormat.V3, v3Full))
        assertEquals(CrliteQueryResult.REVOKED, engine.query(anyQuery))
        assertEquals(CrliteQueryResult.NO_SCTS, engine.query(anyQuery.newBuilder().scts(emptyList()).build()))
        engine.clear()
        assertEquals(CrliteQueryResult.NO_DATA, engine.query(anyQuery))
        assertNull(engine.coverageEndMillis)
        engine.close()
        assertEquals(CrliteQueryResult.ENGINE_ERROR, engine.query(anyQuery))
        engine.close()
    }

    @Test
    fun `coverage end is the latest high of any filter`() {
        val engine = engineWith(ClubcardCorpus.generation("g", FilterFormat.V3, v3Full, v3Delta))
        val highs =
            listOf(v3Full, v3Delta).flatMap { p ->
                ClubcardCorpus.coverage(ClubcardCorpus.file(p).readBytes()).values.map { it.high }
            }
        assertEquals(highs.max().toLong(), engine.coverageEndMillis)
    }

    @Test
    fun `a prepared generation answers alone and leaves the live one untouched`() {
        val engine = engineWith(ClubcardCorpus.generation("live", FilterFormat.V3, v3Full))
        val prepared = engine.prepare(ClubcardCorpus.generation("next", FilterFormat.V4, v4Synthetic))
        assertEquals("next", prepared.generationId)
        assertEquals(CrliteQueryResult.REVOKED, engine.query(anyQuery))
        assertEquals(CrliteQueryResult.NOT_COVERED, prepared.query(anyQuery))
        engine.activate(prepared)
        assertEquals(CrliteQueryResult.NOT_COVERED, engine.query(anyQuery))
        prepared.close()
        assertEquals(CrliteQueryResult.NOT_COVERED, engine.query(anyQuery), "close() after activate() is a no-op")
        assertEquals(CrliteQueryResult.NOT_COVERED, prepared.query(anyQuery))
    }

    @Test
    fun `activate refuses a discarded, an active or a foreign prepared generation`() {
        val engine = KotlinRevocationEngine()
        val generation = ClubcardCorpus.generation("g", FilterFormat.V3, v3Full)
        val discarded = engine.prepare(generation).also { it.close() }
        assertEquals(CrliteQueryResult.ENGINE_ERROR, discarded.query(anyQuery))
        assertTrue("closed" in assertFailsWith<IllegalStateException> { engine.activate(discarded) }.message!!)
        val active = engine.prepare(generation).also { engine.activate(it) }
        assertTrue("active" in assertFailsWith<IllegalStateException> { engine.activate(active) }.message!!)
        val foreign = KotlinRevocationEngine().prepare(generation)
        assertFailsWith<IllegalArgumentException> { engine.activate(foreign) }
        val fake =
            object : PreparedGeneration {
                override val generationId = "fake"

                override fun query(q: CrliteQuery) = CrliteQueryResult.NOT_REVOKED

                override fun close() = Unit
            }
        assertFailsWith<IllegalArgumentException> { engine.activate(fake) }
    }

    @Test
    fun `a corrupt or mislabelled generation throws from prepare and the live one stays`() {
        val engine = engineWith(ClubcardCorpus.generation("live", FilterFormat.V3, v3Full))
        val bytes = ClubcardCorpus.file(v3Full).readBytes()
        val corrupt =
            ClubcardCorpus
                .generation("corrupt", FilterFormat.V3, mapOf("f" to bytes))
                .newBuilder()
                .file("f", bytes.copyOf(bytes.size / 2))
                .build()
        assertTrue("malformed" in assertFailsWith<IllegalArgumentException> { engine.prepare(corrupt) }.message!!)
        val mislabelled = ClubcardCorpus.generation("v4-as-v3", FilterFormat.V3, v4Synthetic)
        assertTrue(
            "encoded as V4" in assertFailsWith<IllegalArgumentException> { engine.prepare(mislabelled) }.message!!,
        )
        val unknownPrefix =
            ClubcardCorpus
                .generation("bad-prefix", FilterFormat.V3, mapOf("f" to bytes))
                .newBuilder()
                .file("f", byteArrayOf(9, 0) + bytes.copyOfRange(2, bytes.size))
                .build()
        assertFailsWith<IllegalArgumentException> { engine.prepare(unknownPrefix) }
        assertEquals("live", engine.toString().substringAfter("live=").trimEnd(')'))
        assertEquals(CrliteQueryResult.REVOKED, engine.query(anyQuery))
    }

    @Test
    fun `prepare and activate throw after close, and close is idempotent`() {
        val engine = KotlinRevocationEngine()
        val generation = ClubcardCorpus.generation("g", FilterFormat.V3, v3Full)
        val prepared = engine.prepare(generation)
        engine.close()
        engine.close()
        assertFailsWith<IllegalStateException> { engine.prepare(generation) }
        assertFailsWith<IllegalStateException> { engine.activate(prepared) }
        assertNull(engine.coverageEndMillis)
    }

    @Test
    fun `install closes the prepared generation when activate throws`() {
        val closed = AtomicBoolean(false)
        val engine =
            object : RevocationEngine {
                override val formats = setOf(FilterFormat.V3)
                override val coverageEndMillis: Long? = null

                override fun prepare(generation: GenerationFiles): PreparedGeneration =
                    object : PreparedGeneration {
                        override val generationId = generation.generationId

                        override fun query(q: CrliteQuery) = CrliteQueryResult.NO_DATA

                        override fun close() = closed.set(true)
                    }

                override fun activate(prepared: PreparedGeneration): Unit = error("refused")

                override fun query(q: CrliteQuery) = CrliteQueryResult.NO_DATA

                override fun close() = Unit
            }
        assertFailsWith<IllegalStateException> {
            engine.install(
                ClubcardCorpus.generation("g", FilterFormat.V3, v3Full),
            )
        }
        assertTrue(closed.get())
        engine.clear()
        assertEquals("g", KotlinRevocationEngine().install(ClubcardCorpus.generation("g", FilterFormat.V3, v3Full)))
    }

    @Test
    fun `concurrent queries see the old or the new generation, never a mix, and close drains them`() {
        val old = ClubcardCorpus.generation("old", FilterFormat.V3, v3Full, v3Delta)
        val new = ClubcardCorpus.generation("new", FilterFormat.V4, v4Synthetic, v4Delta)
        val queries = (goldens("compat-full") + goldens("synthetic")).map { it.query }.filter { it.scts.isNotEmpty() }
        val before = engineWith(old).let { e -> queries.map { e.query(it) } }
        val after = engineWith(new).let { e -> queries.map { e.query(it) } }
        assertTrue(before.zip(after).count { (a, b) -> a != b } > 100, "the generations disagree often enough to tell")

        val engine = engineWith(old)
        val threads = 8
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        val stop = AtomicBoolean(false)
        val bad = java.util.concurrent.ConcurrentLinkedQueue<String>()
        val afterClose = java.util.concurrent.ConcurrentLinkedQueue<CrliteQueryResult>()
        try {
            repeat(threads) { t ->
                pool.execute {
                    start.await()
                    var i = t
                    while (!stop.get()) {
                        val k = i++ % queries.size
                        val r = engine.query(queries[k])
                        if (r != before[k] && r != after[k] && r != CrliteQueryResult.ENGINE_ERROR) bad += "$k: $r"
                    }
                }
            }
            start.countDown()
            repeat(20) {
                engine.activate(engine.prepare(if (it % 2 == 0) new else old))
                Thread.sleep(5)
            }
            engine.close()
            repeat(threads) { afterClose += engine.query(queries[it]) }
        } finally {
            stop.set(true)
            pool.shutdown()
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        }
        assertTrue(bad.isEmpty(), "${bad.size} answers matched neither generation; first: ${bad.firstOrNull()}")
        assertEquals(List(threads) { CrliteQueryResult.ENGINE_ERROR }, afterClose.toList())
    }

    @Test
    fun `the seam's value types compare by content`() {
        val sct = anyQuery.scts.first()
        assertEquals(sct, sct.newBuilder().build())
        assertNotEquals(sct, sct.newBuilder().timestampMillis(sct.timestampMillis + 1).build())
        assertEquals(anyQuery, anyQuery.newBuilder().build())
        assertEquals(anyQuery.hashCode(), anyQuery.newBuilder().build().hashCode())
        assertNotEquals(anyQuery, anyQuery.newBuilder().serial(byteArrayOf(1)).build())
    }
}
