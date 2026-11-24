// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class, RevoktTestingApi::class)

package dev.revokt.engine.walker

import dev.revokt.CrliteQueryResult
import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.PathReason
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.SignatureVerifier
import dev.revokt.Verdict
import dev.revokt.VerifyResult
import dev.revokt.engine.evaluate.Run
import dev.revokt.engine.evaluate.StubEngine
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.walker.WalkerFuzzInput.ThrowKind
import dev.revokt.testing.AlgMismatch
import dev.revokt.testing.AttackerMutation
import dev.revokt.testing.ChainGenerator
import dev.revokt.testing.DropIntermediate
import dev.revokt.testing.NameEncoding
import dev.revokt.testing.Recover
import dev.revokt.testing.ReferenceWalker
import dev.revokt.testing.SplitMix64
import dev.revokt.testing.SymOids
import dev.revokt.testing.SymVerifier
import dev.revokt.testing.UnsupportedOwnSig
import dev.revokt.testing.World
import dev.revokt.testing.WorldMutation
import java.io.IOException

/**
 * One walker-fuzzer input checked against spec §9.1's P1–P8 (`WalkerFuzzTest`). The world is
 * `ChainGenerator.generate` of the input; both walkers use the platform canonicaliser, and each walk starts with the
 * cross-call memo cleared. The decision runs through `decideWalkerHarness` (no step-3 `MAX_PRESENTED` cut, so a spent
 * walk reaches steps 6 to 8) inside `evaluate`, under `DEFAULT`, with a CRLite stub that maps the honest key to
 * `REVOKED` when [WalkerFuzzInput.revoked] (else `NOT_REVOKED`) and every other key to `NOT_ENROLLED`, and a fake
 * fallback that returns the reference walker's shortest path. That fallback never supplies a path in a generated world: a
 * `Budget` walk needs more than `FALLBACK_MAX_PRESENTED` certificates, where it is skipped, and the generator writes no
 * SKI-only link, so P2's fallback-key branch cannot fail here (#316 review N4); only its call count (P5) is exercised.
 * With a [ThrowKind] the verifier throws on every link
 * under one key of the world; P3, P6 and P8 are then not checked (the honest link may throw).
 *
 * Beyond §9.1, these hold in the code and are asserted too (tests only, as decided on #144): P1's path
 * is leaf-first, within `MAX_DEPTH`, without repeats and with JDK-CA issuers; P2's issuer identity (a found key is the
 * honest one, or a recovered key under `Recover(leaf, CertifiedBy)`); P4's equal `NotFound` walks and reported anchor;
 * P5's exact fallback count; P6 as `verifications == candidatesExplored == depth + 1`; P7's interrupt flag (#134 F6);
 * and the production `decide` agreeing with the harness within `MAX_PRESENTED`.
 */
internal class WalkerFuzzRun(
    private val input: WalkerFuzzInput,
) {
    private val world = ChainGenerator.generate(input.seed, input.mutations, input.depth, input.anchors)
    private val at = "$input, applied ${world.mutations}"
    private val index = CandidateIndex(world.anchors)
    private val snapshot = WalkerHarness.snapshot(world.anchors)
    private val sym = world.verifier()

    /** The SPKI whose links throw, when [WalkerFuzzInput.throwKind] is set. */
    private val throwing: ByteArray? =
        if (input.throwKind == ThrowKind.NONE) {
            null
        } else {
            world.specs[input.throwSelector.mod(world.specs.size)].key.spki
        }

    /** The walker's throws so far: only [verifier] counts, so P7's interrupt expectation reads the walker's alone. */
    private var throws = 0

    /** The fuzzer's verifier: [sym], throwing on [throwing]'s links; [counted] for the walker's, not the reference's. */
    private inner class Throwing(
        private val counted: Boolean,
    ) : SignatureVerifier {
        override fun verify(
            sigAlg: ByteArray,
            spki: ByteArray,
            message: ByteArray,
            signature: ByteArray,
        ): VerifyResult {
            if (throwing != null && spki.contentEquals(throwing)) {
                if (counted) throws++
                throw throwable(input.throwKind)
            }
            return sym.verify(sigAlg, spki, message, signature)
        }

        override fun unsupportedOids(): Set<String> = sym.unsupportedOids()
    }

    private val verifier: SignatureVerifier = Throwing(counted = true)

    /** The reference and the fake fallback built on it, with their own verifier, which never sets the flag back. */
    private val reference = ReferenceWalker(world.anchors, Throwing(counted = false))

    /** Recover with an anchor-certified key on any child, and on the leaf. */
    private val certified = world.mutations.filterIsInstance<Recover>().filter { it.certifiedBy != null }
    private val leafCertified = certified.any { it.child.mod(world.depth + 1) == 0 }

    fun check() {
        val presented = world.presented
        val refKeys = reference.walk(presented)
        val byName = reference.walkByName(presented)
        val walk = walk(presented, verifier)
        p1(walk)
        p2(walk, refKeys, byName)
        p5(walk)
        val evaluated = evaluate(world, verifier, reference)
        decisionProperties(walk, evaluated, refKeys)
        production(evaluated.decision)
        p4(walk)
        if (input.throwKind == ThrowKind.NONE) {
            p6(walk)
            p8(walk, evaluated)
            p3(walk, evaluated)
        }
    }

    private fun fail(message: String): Nothing = throw AssertionError("$message; $at")

    private fun ensure(
        condition: Boolean,
        message: () -> String,
    ) {
        if (!condition) fail(message())
    }

    private fun walk(
        presented: List<ByteArray>,
        v: SignatureVerifier,
    ): Walk {
        val certs =
            presented.map {
                val parsed = CertificateParser.parse(it) as? CertificateParse.Parsed ?: fail("a generated cert fails")
                index.cert(parsed.certificate)
            }
        return interruptChecked("the walk") {
            reconstruct(certs, index, v, v.unsupportedOids(), lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES))
        }
    }

    /**
     * P7, #134 F6: [block] with the interrupt flag cleared first; afterwards the flag is set exactly when the walker's
     * verifier threw an `InterruptedException` during it, which the walker caught and set the flag again for.
     */
    private fun <T> interruptChecked(
        what: String,
        block: () -> T,
    ): T {
        Thread.interrupted()
        val before = throws
        val result = block()
        val interrupted = Thread.interrupted()
        val expected = input.throwKind == ThrowKind.INTERRUPTED && throws > before
        ensure(interrupted == expected) { "P7: interrupt flag $interrupted after $what, ${throws - before} throws" }
        return result
    }

    /** P1: the found path is sound under the fuzzer's verifier, a throwing link never verified. */
    private fun p1(walk: Walk) {
        if (walk !is Walk.Found) return
        ensure(walk.leafKey == walk.path.certs[1].spkiHash) { "P1: the leaf key is not the path's second" }
        WalkSoundness.assertSound(walk.path, walk.path.certs[0], index, { child, issuer ->
            !(throwing != null && issuer.spki.contentEquals(throwing)) &&
                sym.verify(child.tbsSigAlg, issuer.spki, child.tbs, child.sig) == VerifyResult.VERIFIED
        }, "P1: $at")
    }

    /** P2: the bracket against the reference, and the generator's issuer identity. */
    private fun p2(
        walk: Walk,
        refKeys: Set<String>,
        byName: Set<String>,
    ) {
        when (walk) {
            is Walk.Found -> {
                val key = walk.leafKey.hex()
                ensure(key in refKeys) { "P2: Found key $key not in the reference's $refKeys" }
                val allowed = if (leafCertified) world.recoveredKeys + world.honestKey else listOf(world.honestKey)
                ensure(key in allowed) { "P2: Found key $key is neither the honest key nor a certified recovery" }
            }

            is Walk.NotFound -> {
                ensure(byName.isEmpty()) { "P2: NotFound but the reference has $byName by name" }
            }

            // The walk stops at its first path, so a spent one has none; the decision half is in decisionProperties.
            is Walk.Budget -> {}
        }
    }

    /** P5: one budget, spent exactly on `Budget` (the generator writes no nameConstraints). */
    private fun p5(walk: Walk) {
        val s = walk.stats
        ensure(s.verifications <= s.candidatesExplored) { "P5: ${s.verifications} verifications > explorations" }
        ensure(s.candidatesExplored <= RevoktLimits.MAX_EXPLORED) { "P5: ${s.candidatesExplored} explorations" }
        if (walk is Walk.Budget) {
            ensure(s.candidatesExplored == RevoktLimits.MAX_EXPLORED) { "P5: Budget with the budget unspent: $s" }
        }
    }

    private class Decided(
        val verdict: Verdict,
        val decision: PathDecision,
        val fallbackCalls: Int,
    )

    private fun evaluate(
        w: World,
        v: SignatureVerifier,
        ref: ReferenceWalker,
    ): Decided {
        val fallback = FakeFallback { ref.path(it) }
        val honest = w.honestKey
        val engine =
            StubEngine { key ->
                when {
                    key.hex() != honest -> CrliteQueryResult.NOT_ENROLLED
                    input.revoked -> CrliteQueryResult.REVOKED
                    else -> CrliteQueryResult.NOT_REVOKED
                }
            }
        val run =
            Run(w.presented, engine = engine) { now ->
                val context = DecideContext(v, v.unsupportedOids(), memo(), fallback, now, platformOnly = false)
                decideWalkerHarness(w.presented, index, snapshot, context)
            }
        val evaluated = interruptChecked("evaluate") { run.evaluate() }
        val decision = evaluated.decision ?: fail("no decision: ${evaluated.verdict}")
        return Decided(evaluated.verdict, decision, fallback.calls)
    }

    private fun memo() =
        lruMap<Pair<okio.ByteString, okio.ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)

    /** The decision-level halves of P1, P2, P5 and P7. */
    private fun decisionProperties(
        walk: Walk,
        d: Decided,
        refKeys: Set<String>,
    ) {
        val decision = d.decision
        val status = decision.path.status
        ensure(decision.detail.walkStats == walk.stats) { "decide's walk differs: ${decision.detail.walkStats}" }
        if (walk is Walk.Found) {
            ensure(status == PathStatus.FOUND && !decision.detail.usedFallback) { "P1: Found walk decided $status" }
            ensure(decision.detail.reportedPathSha256s == walk.path.certs.map { it.bytesHash }) { "P1: reported path" }
            ensure(decision.issuerKeys == listOf(walk.leafKey)) { "P1: decision keys ${decision.issuerKeys}" }
        }
        // P2: a spent walk carries no key; only a fallback path's key, one of the reference's, is evaluated.
        if (status == PathStatus.PATH_BUDGET_EXCEEDED) {
            val keys = decision.issuerKeys
            ensure(
                keys.isEmpty() || (keys.size == 1 && decision.detail.usedFallback && keys[0].hex() in refKeys),
            ) { "P2: PATH_BUDGET_EXCEEDED with keys $keys" }
        }
        // P5: the fallback runs once on a walk without a path within FALLBACK_MAX_PRESENTED, else never.
        val expected = if (walk !is Walk.Found && world.presented.size <= RevoktLimits.FALLBACK_MAX_PRESENTED) 1 else 0
        ensure(d.fallbackCalls == expected) { "P5: the fallback ran ${d.fallbackCalls} times, expected $expected" }
        // P7: no ENGINE_ERROR, which DEFAULT would allow.
        ensure(Rule.ENGINE_ERROR !in d.verdict.rules) { "P7: ENGINE_ERROR in ${d.verdict}" }
        ensure(d.verdict.findings.none { it is Finding.EngineError }) { "P7: an EngineError finding: ${d.verdict}" }
    }

    /** The production `decide` agrees with the harness within step 3's cut, and cuts above it with no walk. */
    private fun production(harness: PathDecision) {
        val fallback = FakeFallback { reference.path(it) }
        val context =
            DecideContext(verifier, verifier.unsupportedOids(), memo(), fallback, WalkerHarness.NOW, false)
        val prod = interruptChecked("the production decide") { decide(world.presented, index, snapshot, context) }
        val within =
            world.presented.size <= RevoktLimits.MAX_PRESENTED &&
                world.presented.sumOf { it.size.toLong() } <= RevoktLimits.MAX_PRESENTED_BYTES
        if (within) {
            ensure(prod.path.status == harness.path.status && prod.path.reason == harness.path.reason) {
                "decide ${prod.path.status}(${prod.path.reason}) differs from the harness's ${harness.path.status}"
            }
            ensure(prod.issuerKeys == harness.issuerKeys) { "decide's keys differ from the harness's" }
        } else {
            ensure(
                prod.path.status == PathStatus.PATH_BUDGET_EXCEEDED &&
                    prod.path.reason == PathReason.EXPLORATION_BUDGET &&
                    prod.issuerKeys.isEmpty() &&
                    fallback.calls == 0,
            ) { "the step-3 cut: ${prod.path.status}(${prod.path.reason}), fallback ${fallback.calls}" }
        }
    }

    /** P4: the same world in a second order of `presented[1..]`. */
    private fun p4(walk: Walk) {
        val presented = world.presented
        val other = listOf(presented[0]) + SplitMix64(input.permuteSeed).shuffled(presented.drop(1))
        val again = walk(other, verifier)
        if (walk is Walk.Budget || again is Walk.Budget) {
            for ((a, b) in listOf(walk to again, again to walk)) {
                ensure(a !is Walk.Budget || b is Walk.Budget || b is Walk.Found) { "P4: Budget against $b" }
            }
            return
        }
        ensure(walk::class == again::class) { "P4: $walk in one order, $again in the other" }
        if (walk is Walk.Found && again is Walk.Found) {
            if (!leafCertified) ensure(walk.leafKey == again.leafKey) { "P4: the leaf key depends on the order" }
            if (certified.isEmpty()) {
                ensure(
                    walk.path.certs
                        .last()
                        .bytesHash ==
                        again.path.certs
                            .last()
                            .bytesHash,
                ) {
                    "P4: the anchor depends on the order"
                }
            }
        }
        if (walk is Walk.NotFound && again is Walk.NotFound) {
            ensure(walk.reason == again.reason) { "P4: NotFound reasons ${walk.reason}, ${again.reason}" }
            ensure(walk.stats.candidatesExplored == again.stats.candidatesExplored) { "P4: NotFound explorations" }
            ensure(walk.unsupportedOids == again.unsupportedOids) { "P4: NotFound unsupportedOids" }
        }
    }

    /** P6: an unmutated world costs one exploration and one verification per link. */
    private fun p6(walk: Walk) {
        if (world.mutations.isNotEmpty()) return
        val links = world.depth + 1
        ensure(walk is Walk.Found && walk.leafKey.hex() == world.honestKey) { "P6: honest world $walk" }
        ensure(walk.stats.verifications == links && walk.stats.candidatesExplored == links) {
            "P6: ${walk.stats} for $links links"
        }
    }

    /** P8: honest acceptance under world mutations only. */
    private fun p8(
        walk: Walk,
        d: Decided,
    ) {
        val applied = world.mutations
        if (applied.any { it !is WorldMutation }) return
        val path = d.decision.path
        val small = world.presented.size <= RevoktLimits.FALLBACK_MAX_PRESENTED
        val dropped = applied.filterIsInstance<DropIntermediate>()
        val unsupported = applied.any { it is UnsupportedOwnSig }
        when {
            applied.all { it is NameEncoding || it is AlgMismatch } -> {
                honestAccepted(walk, d)
            }

            unsupported && dropped.isEmpty() -> {
                ensure(walk is Walk.NotFound && SymOids.UNSUPPORTED_SIGNATURE in walk.unsupportedOids) {
                    "P8: UnsupportedOwnSig $walk"
                }
                notFound(path, small, PathReason.UNSUPPORTED_ALGORITHM)
            }

            dropped.isNotEmpty() && !unsupported -> {
                // A3: the reason is the leaf level's, so only a dropped leaf issuer leaves the leaf no candidate.
                val leafIssuer = dropped.any { it.target.mod(world.depth) == 0 }
                val reason = if (leafIssuer) NoIssuerReason.NO_CANDIDATE else NoIssuerReason.UNANCHORED
                ensure(walk is Walk.NotFound && walk.reason == reason) { "P8: DropIntermediate $walk, want $reason" }
                notFound(path, small, noIssuerReason(reason))
            }

            // Both: the reason depends on which of them the leaf level meets first; the walk still ends without a path.
            else -> {
                ensure(walk is Walk.NotFound) { "P8: UnsupportedOwnSig and DropIntermediate $walk" }
                ensure(
                    if (small) path.status == PathStatus.NO_ISSUER else path.reason == PathReason.FALLBACK_LIMIT,
                ) { "P8: UnsupportedOwnSig and DropIntermediate decided ${path.status}(${path.reason})" }
            }
        }
    }

    /** P8's first clause: an honest world is `Found` with the honest key, and rejected exactly when it is revoked. */
    private fun honestAccepted(
        walk: Walk,
        d: Decided,
    ) {
        val path = d.decision.path
        ensure(walk is Walk.Found && walk.leafKey.hex() == world.honestKey) { "P8: honest world $walk" }
        ensure(path.status == PathStatus.FOUND) { "P8: honest world decided ${path.status}" }
        ensure((d.verdict is Verdict.Rejected) == input.revoked) { "P8: verdict ${d.verdict}" }
        if (d.verdict is Verdict.Rejected) ensure(d.verdict.rule == Rule.REVOKED) { "P8: ${d.verdict.rule}" }
    }

    /** A2: `NO_ISSUER(reason)` within `FALLBACK_MAX_PRESENTED`, `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)` above it. */
    private fun notFound(
        path: Finding.Path,
        small: Boolean,
        reason: PathReason,
    ) {
        val (status, want) =
            if (small) PathStatus.NO_ISSUER to reason else PathStatus.PATH_BUDGET_EXCEEDED to PathReason.FALLBACK_LIMIT
        ensure(
            path.status == status && path.reason == want,
        ) { "P8: ${path.status}(${path.reason}), want $status($want)" }
    }

    /** P3: attacker mutations never improve the honest world's verdict. */
    private fun p3(
        walk: Walk,
        d: Decided,
    ) {
        if (world.mutations.none { it is AttackerMutation } || leafCertified) return
        val honest =
            ChainGenerator.generate(
                input.seed,
                input.mutations.filterIsInstance<WorldMutation>(),
                input.depth,
                input.anchors,
            )
        ensure(honest.honestKey == world.honestKey) { "P3: the honest world has another honest key" }
        ensure(honest.anchors.map { it.toList() } == world.anchors.map { it.toList() }) { "P3: other anchors" }
        val honestSym = SymVerifier(honest.ok, honest.unsupported)
        val honestWalk = walk(honest.presented, honestSym)
        // A1: an anchor-certified CA supplied the path a world mutation removed. The walk found the honest key (P2), so
        // the verdict follows its CRLite answer, whatever the honest world's was.
        if (certified.isNotEmpty() && honestWalk is Walk.NotFound && walk is Walk.Found) {
            val bv = d.verdict
            ensure((bv is Verdict.Rejected) == input.revoked && (bv !is Verdict.Rejected || bv.rule == Rule.REVOKED)) {
                "P3: the certified bridge decided $bv"
            }
            return
        }
        val h = evaluate(honest, honestSym, ReferenceWalker(honest.anchors, honestSym))
        val hv = h.verdict
        val mv = d.verdict
        if (hv is Verdict.Rejected) {
            ensure(mv is Verdict.Rejected && mv.rule in setOf(Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED)) {
                "P3: honest $hv, mutated $mv"
            }
        }
        val limit =
            walk is Walk.Budget ||
                h.decision.path.status == PathStatus.PATH_BUDGET_EXCEEDED ||
                d.decision.path.status == PathStatus.PATH_BUDGET_EXCEEDED
        if (!limit) {
            ensure((mv is Verdict.Rejected) == (hv is Verdict.Rejected) && mv.rule == hv.rule) {
                "P3: honest $hv, mutated $mv with no limit hit"
            }
        }
    }

    private companion object {
        fun throwable(kind: ThrowKind): Throwable =
            when (kind) {
                ThrowKind.NONE -> error("no throw")
                ThrowKind.RUNTIME -> IllegalStateException("walker fuzz: the verifier throws")
                ThrowKind.IO -> IOException("walker fuzz: the verifier throws")
                ThrowKind.ASSERTION -> AssertionError("walker fuzz: the verifier throws")
                ThrowKind.STACK_OVERFLOW -> StackOverflowError("walker fuzz: the verifier throws")
                ThrowKind.INTERRUPTED -> InterruptedException("walker fuzz: the verifier throws")
            }
    }
}
