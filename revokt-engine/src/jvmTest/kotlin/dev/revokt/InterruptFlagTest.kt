// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.walker.CandidateIndex
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.engine.walker.WalkerHarness
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A verifier, canonicaliser, fallback or exemption that throws `InterruptedException` is caught by the §5.5 catch
 * rule like any other non-fatal throw, and the thread's interrupt flag, which the thrower cleared, is set again (#196
 * F6), as it is at the boundary itself. JVM only: Kotlin/Native has no interrupt flag. Each test clears the flag.
 */
@OptIn(RevoktTestingApi::class)
class InterruptFlagTest {
    private val h = Honest()

    private val honest =
        h.fixture("interrupt", presented = listOf(h.leaf, h.intermediate), walk = ExpectedWalk.found(h.path))

    /** The leaf alone: `NO_ISSUER(NO_CANDIDATE)`, so the fallback and a `NO_ISSUER` exemption run. */
    private val leafOnly =
        h.fixture("interrupt", presented = listOf(h.leaf), walk = ExpectedWalk.notFound(NoIssuerReason.NO_CANDIDATE))

    private fun interrupts(): Nothing = throw InterruptedException("interrupted")

    /** Runs [block] on a clear flag, asserts the flag is set after it, and clears it again. */
    private fun <T> keepsInterrupt(block: () -> T): T {
        assertFalse(Thread.interrupted(), "the flag starts clear")
        try {
            val result = block()
            assertTrue(Thread.currentThread().isInterrupted, "the interrupt flag is set again")
            return result
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `a verifier's InterruptedException is INVALID with a VerifierError and keeps the interrupt`() {
        val throwing =
            object : SignatureVerifier {
                override fun verify(
                    sigAlg: ByteArray,
                    spki: ByteArray,
                    message: ByteArray,
                    signature: ByteArray,
                ): VerifyResult = interrupts()

                override fun unsupportedOids(): Set<String> = emptySet()
            }
        val v = keepsInterrupt { EvaluatorRig(honest, verifier = { throwing }).presented(honest.presented) }
        assertTrue(v.findings.any { it is Finding.VerifierError })
        assertEquals(
            PathStatus.NO_ISSUER,
            v.findings
                .filterIsInstance<Finding.Path>()
                .single()
                .status,
        )
    }

    @Test
    fun `a canonicaliser's InterruptedException is no canonical match and keeps the interrupt`() {
        val rig = EvaluatorRig(honest)
        val index = CandidateIndex(honest.snapshot, customCanonicaliser = true) { interrupts() }
        // The anchors' canonical subjects are computed now, so the build already sets the flag.
        assertTrue(Thread.interrupted(), "the index build kept the interrupt")
        rig.indexed = IndexedSnapshot(WalkerHarness.snapshot(honest.snapshot), index)
        val v = keepsInterrupt { rig.presented(honest.presented) }
        assertEquals(
            PathStatus.FOUND,
            v.findings
                .filterIsInstance<Finding.Path>()
                .single()
                .status,
        )
    }

    @Test
    fun `a fallback's InterruptedException is a failed fallback and keeps the interrupt`() {
        val fallback =
            object : PathBuilderFallback {
                override fun build(
                    chainDer: List<ByteArray>,
                    anchors: AnchorSnapshot,
                    nowMillis: Long,
                ): List<ByteArray> = interrupts()
            }
        val v = keepsInterrupt { EvaluatorRig(leafOnly, fallback = fallback).presented(leafOnly.presented) }
        val path = v.findings.filterIsInstance<Finding.Path>().single()
        assertEquals(PathStatus.NO_ISSUER, path.status)
        assertEquals(
            FallbackReason.FAILED,
            v.findings
                .filterIsInstance<Finding.FallbackNotUsed>()
                .single()
                .reason,
        )
    }

    @Test
    fun `an exemption's InterruptedException is not exempt and keeps the interrupt, also inside or`() {
        val throwing = Exemption { interrupts() }
        val strict = { e: Exemption ->
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_ISSUER, e)
                .build()
        }
        val alone =
            keepsInterrupt { EvaluatorRig(leafOnly, strict(throwing), snapshot()).presented(leafOnly.presented) }
        assertIs<Verdict.Rejected>(alone)
        assertTrue(Rule.ENGINE_ERROR in alone.rules)
        // `or` absorbs the throw where the other side decides: exempt, and the interrupt is still kept.
        val either = strict(throwing or Exemption { true })
        val v = keepsInterrupt { EvaluatorRig(leafOnly, either, snapshot()).presented(leafOnly.presented) }
        assertIs<Verdict.Accepted>(v)
    }

    @Test
    fun `an InterruptedException at the boundary is ENGINE_ERROR and keeps the interrupt`() {
        val v = keepsInterrupt { EvaluatorRig(honest, clock = { interrupts() }).presented(honest.presented) }
        assertTrue(Rule.ENGINE_ERROR in v.rules)
    }
}
