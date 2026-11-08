// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestCert
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `ExemptionContext` and `Exemption.anchorIn` as spec §4 declares them (#120). */
@OptIn(RevoktTestingApi::class)
class ExemptionTest {
    private fun hash(b: Int) = ByteArray(32) { b.toByte() }

    private fun path(anchor: ByteArray?) =
        Finding.Path
            .Builder()
            .status(PathStatus.FOUND)
            .source(ChainSource.RECONSTRUCTED)
            .anchorSha256(anchor)
            .build()

    private fun dataState(rules: Set<Rule> = emptySet()) =
        Finding.DataState
            .Builder()
            .dataset(Dataset.CRLITE)
            .rules(rules)
            .build()

    private val chain =
        PresentedChain
            .Builder()
            .certificates(listOf(TestCert().der))
            .build()

    private fun context(anchor: ByteArray? = hash(3)) =
        ExemptionContext
            .Builder()
            .rule(Rule.NO_DATA)
            .chain(chain)
            .path(path(anchor))
            .host("corp.example")
            .nowMillis(1_700_000_000_000)
            .dataStates(mapOf(Dataset.CRLITE to dataState(setOf(Rule.NO_DATA))))
            .build()

    private fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!

    @Test
    fun `a context built from equal inputs is equal, and newBuilder round-trips`() {
        for (same in listOf(context(), context().newBuilder().build())) {
            assertEquals(context(), same)
            assertEquals(context().hashCode(), same.hashCode())
            assertEquals(context().toString(), same.toString())
        }
        assertNotEquals<Any>(context(), "context")
        val text = context().toString()
        for (field in listOf("rule", "chain", "credentialType", "path", "host", "nowMillis", "dataStates")) {
            assertTrue("$field=" in text, "$field missing from $text")
        }
    }

    @Test
    fun `every context field takes part in equality`() {
        val base = context()
        val changed =
            mapOf<String, ExemptionContext.Builder.() -> ExemptionContext.Builder>(
                "rule" to { rule(Rule.STALE) },
                "chain" to {
                    chain(
                        PresentedChain
                            .Builder()
                            .certificates(listOf(TestCert(subject = TestCert.name("other.example")).der))
                            .build(),
                    )
                },
                "path" to { path(path(hash(4))) },
                "host" to { host(null) },
                "nowMillis" to { nowMillis(1) },
                "dataStates" to { dataStates(emptyMap()) },
                // credentialType has one value in M1 (X509), so no second value to differ by.
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `the context builder defaults, its required fields and a read-only copy of the data states`() {
        val given = mutableMapOf(Dataset.CRLITE to dataState())
        val c =
            ExemptionContext
                .Builder()
                .rule(Rule.NO_SCTS)
                .chain(chain)
                .path(path(null))
                .nowMillis(0)
                .dataStates(given)
                .build()
        given.clear()
        assertEquals(mapOf(Dataset.CRLITE to dataState()), c.dataStates)
        @Suppress("UNCHECKED_CAST") // The check is that the read-only view cannot be cast back and changed.
        assertFailsWith<UnsupportedOperationException> {
            (c.dataStates as MutableMap<Dataset, Finding.DataState>).clear()
        }
        assertNull(c.host)
        assertEquals(CredentialType.X509, c.credentialType)
        val builder = { ExemptionContext.Builder().chain(chain) }
        assertEquals("rule is not set", message { builder().path(path(null)).nowMillis(0).build() })
        assertEquals("path is not set", message { builder().rule(Rule.NO_SCTS).nowMillis(0).build() })
        assertEquals("nowMillis is not set", message { builder().rule(Rule.NO_SCTS).path(path(null)).build() })
    }

    @Test
    fun `the chain is null exactly when the credential is not X509`() {
        // M1 has only X509, so an X.509 context without a chain is the one way to break it (spec §4: null for M5's MTC).
        val broken = message { context().newBuilder().chain(null).build() }
        assertTrue("chain is null exactly when credentialType is not X509" in broken, broken)
        assertEquals(chain, context().chain)
    }

    @Test
    fun `anchorIn matches the reported path's anchor by content`() {
        val exemption = Exemption.anchorIn(listOf(hash(1), hash(3)))
        assertTrue(exemption.isExempt(context(hash(3))))
        assertTrue(exemption.isExempt(context(hash(3).copyOf())), "another array with the same content")
        assertFalse(exemption.isExempt(context(hash(4))))
        assertFalse(Exemption.anchorIn(emptyList()).isExempt(context(hash(3))))
    }

    @Test
    fun `anchorIn copies its input, so a later change to an array does not change the match`() {
        val anchor = hash(3)
        val given = mutableListOf(anchor)
        val exemption = Exemption.anchorIn(given)
        anchor[0] = 9
        given.clear()
        assertTrue(exemption.isExempt(context(hash(3))))
        assertFalse(exemption.isExempt(context(anchor)))
    }

    @Test
    fun `a null anchorSha256 never matches`() {
        assertFalse(Exemption.anchorIn(listOf(hash(3))).isExempt(context(null)))
        assertFalse(Exemption.anchorIn(listOf(ByteArray(0))).isExempt(context(null)))
    }

    @Test
    fun `an exemption is a lambda over the context`() {
        val byHost = Exemption { it.host == "corp.example" }
        assertTrue(byHost.isExempt(context()))
        assertFalse(byHost.isExempt(context().newBuilder().host(null).build()))
    }
}
