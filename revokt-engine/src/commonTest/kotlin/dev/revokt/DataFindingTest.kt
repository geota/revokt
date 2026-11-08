// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The data and error findings as spec §4 declares them (#120): `Crlite`, `DataState`, `EngineError` and `Exempted`.
 * Value types, `newBuilder()` round trips, fresh copies and the builder invariants.
 */
@OptIn(RevoktTestingApi::class)
class DataFindingTest {
    private fun hash(b: Int) = ByteArray(32) { b.toByte() }

    private fun assertValueSemantics(
        a: Any,
        same: Any,
    ) {
        assertEquals(a, same)
        assertEquals(a.hashCode(), same.hashCode())
        assertEquals(a.toString(), same.toString())
    }

    private fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!

    private fun crlite() =
        Finding.Crlite
            .Builder()
            .result(CrliteQueryResult.REVOKED)
            .issuerSpkiSha256(hash(4))
            .coverageEndMillis(1_700_000_000_000)
            .build()

    /** Every field set away from its builder default, so a round trip that drops one shows. */
    private fun dataState() =
        Finding.DataState
            .Builder()
            .dataset(Dataset.CRLITE)
            .trustClass(TrustClass.BUNDLED)
            .generationId("seed-2026-11-01")
            .freshness(Freshness.SEED_SIGNED_TIME)
            .fromSeed(true)
            .sourceTimestampMillis(1_700_000_000_000)
            .ageMillis(4 * 86_400_000L)
            .pending(true)
            .clockBehind(true)
            .seedFormat(1)
            .stale(true)
            .rules(setOf(Rule.STALE, Rule.UNSIGNED_DATA))
            .build()

    private fun engineError() =
        Finding.EngineError
            .Builder()
            .message("query threw")
            .producer(EngineErrorProducer.ENGINE)
            .engineName("kotlin")
            .build()

    private fun exempted() =
        Finding.Exempted
            .Builder()
            .rule(Rule.NO_SCTS)
            .build()

    @Test
    fun `each finding built from equal inputs is equal, and newBuilder round-trips`() {
        assertValueSemantics(crlite(), crlite())
        assertValueSemantics(crlite(), crlite().newBuilder().build())
        assertValueSemantics(dataState(), dataState())
        assertValueSemantics(dataState(), dataState().newBuilder().build())
        assertValueSemantics(engineError(), engineError())
        assertValueSemantics(engineError(), engineError().newBuilder().build())
        assertValueSemantics(exempted(), exempted())
        assertValueSemantics(exempted(), exempted().newBuilder().build())
        for (f in listOf(crlite(), dataState(), engineError(), exempted())) assertNotEquals<Any>(f, "finding")
    }

    @Test
    fun `every crlite field takes part in equality and toString prints the key in hex`() {
        val base = crlite()
        assertNotEquals(base, base.newBuilder().result(CrliteQueryResult.NOT_REVOKED).build())
        assertNotEquals(base, base.newBuilder().issuerSpkiSha256(hash(5)).build())
        assertNotEquals(base, base.newBuilder().issuerSpkiSha256(null).build())
        assertNotEquals(base, base.newBuilder().coverageEndMillis(null).build())
        assertEquals(
            "Crlite(result=REVOKED, issuerSpkiSha256=${"04".repeat(32)}, coverageEndMillis=1700000000000)",
            base.toString(),
        )
    }

    @Test
    fun `crlite copies the key it is given and hands out copies`() {
        val key = hash(4)
        val c =
            Finding.Crlite
                .Builder()
                .result(CrliteQueryResult.NO_SCTS)
                .issuerSpkiSha256(key)
                .build()
        key[0] = 9
        c.issuerSpkiSha256!![0] = 9
        assertContentEquals(hash(4), c.issuerSpkiSha256)
        assertNull(c.coverageEndMillis)
        assertEquals("result is not set", message { Finding.Crlite.Builder().build() })
    }

    @Test
    fun `every data state field takes part in equality`() {
        val base = dataState()
        val changed =
            mapOf<String, Finding.DataState.Builder.() -> Finding.DataState.Builder>(
                "trustClass" to { trustClass(TrustClass.SIGNED) },
                "generationId" to { generationId("other") },
                "freshness" to { freshness(Freshness.RECORD_LAST_MODIFIED) },
                "fromSeed" to { fromSeed(false) },
                "sourceTimestampMillis" to { sourceTimestampMillis(1) },
                "ageMillis" to { ageMillis(0) },
                "pending" to { pending(false) },
                "clockBehind" to { clockBehind(false) },
                "seedFormat" to { seedFormat(null) },
                "stale" to { stale(false) },
                "rules" to { rules(setOf(Rule.STALE)) },
                // dataset has one value in M1 (CRLITE), so no second value to differ by.
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
        val text = base.toString()
        for (field in listOf("dataset") + changed.keys) assertTrue("$field=" in text, "$field missing from $text")
        assertTrue(text.startsWith("DataState(dataset=CRLITE, trustClass=BUNDLED, generationId=seed-2026-11-01"), text)
    }

    @Test
    fun `data state rules are a read-only copy in precedence order`() {
        val given = linkedSetOf(Rule.UNSIGNED_DATA, Rule.NO_DATA, Rule.STALE)
        val d =
            dataState()
                .newBuilder()
                .rules(given)
                .build()
        given.clear()
        assertEquals(listOf(Rule.NO_DATA, Rule.STALE, Rule.UNSIGNED_DATA), d.rules.toList())
        assertTrue("rules=[NO_DATA, STALE, UNSIGNED_DATA]" in d.toString(), d.toString())
        @Suppress("UNCHECKED_CAST") // The check is that the read-only view cannot be cast back and changed.
        assertFailsWith<UnsupportedOperationException> { (d.rules as MutableSet<Rule>).add(Rule.REVOKED) }
    }

    @Test
    fun `the data state builder defaults, its required field and its invariant`() {
        val d =
            Finding.DataState
                .Builder()
                .dataset(Dataset.CRLITE)
                .build()
        assertNull(d.trustClass)
        assertNull(d.generationId)
        assertNull(d.freshness)
        assertNull(d.sourceTimestampMillis)
        assertNull(d.ageMillis)
        assertNull(d.seedFormat)
        assertEquals(false, d.fromSeed)
        assertEquals(false, d.pending)
        assertEquals(false, d.clockBehind)
        assertEquals(false, d.stale)
        assertEquals(emptySet(), d.rules)
        assertEquals("dataset is not set", message { Finding.DataState.Builder().build() })
        // trustClass == null ⇔ generationId == null, broken in both directions.
        val noClass = message { dataState().newBuilder().trustClass(null).build() }
        assertTrue("trustClass is null exactly when generationId is" in noClass, noClass)
        val noId = message { dataState().newBuilder().generationId(null).build() }
        assertTrue("trustClass is null exactly when generationId is" in noId, noId)
        assertEquals(
            d,
            dataState()
                .newBuilder()
                .trustClass(null)
                .generationId(null)
                .freshness(null)
                .fromSeed(false)
                .sourceTimestampMillis(null)
                .ageMillis(null)
                .pending(false)
                .clockBehind(false)
                .seedFormat(null)
                .stale(false)
                .rules(emptySet())
                .build(),
        )
    }

    @Test
    fun `an engine error names its engine whenever the engine produced it`() {
        val base = engineError()
        assertNotEquals(base, base.newBuilder().message("other").build())
        assertNotEquals(base, base.newBuilder().engineName("upki").build())
        assertNotEquals(base, base.newBuilder().producer(EngineErrorProducer.BOUNDARY).build())
        assertEquals("EngineError(message=query threw, producer=ENGINE, engineName=kotlin)", base.toString())
        val broken = message { base.newBuilder().engineName(null).build() }
        assertTrue("engineName is set whenever producer is ENGINE" in broken, broken)
        // The other producers may carry no engine name.
        for (producer in EngineErrorProducer.entries - EngineErrorProducer.ENGINE) {
            assertNull(
                base
                    .newBuilder()
                    .producer(producer)
                    .engineName(null)
                    .build()
                    .engineName,
            )
        }
        assertEquals(
            "message is not set",
            message {
                Finding.EngineError
                    .Builder()
                    .producer(EngineErrorProducer.BOUNDARY)
                    .build()
            },
        )
        assertEquals(
            "producer is not set",
            message {
                Finding.EngineError
                    .Builder()
                    .message("m")
                    .build()
            },
        )
    }

    @Test
    fun `an exempted finding names its rule`() {
        assertNotEquals(exempted(), exempted().newBuilder().rule(Rule.NOT_ENROLLED).build())
        assertEquals("Exempted(rule=NO_SCTS)", exempted().toString())
        assertEquals("rule is not set", message { Finding.Exempted.Builder().build() })
    }

    @Test
    fun `findings of different subtypes are never equal`() {
        val findings: List<Finding> = listOf(crlite(), dataState(), engineError(), exempted())
        for (a in findings) for (b in findings) if (a !== b) assertNotEquals(a, b)
    }
}
