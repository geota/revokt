// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.walker

import dev.revokt.FallbackReason
import dev.revokt.NoIssuerReason
import dev.revokt.PathReason
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.canonicalSubject
import dev.revokt.engine.evaluate.noGeneration
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.FixtureWorld.Companion.TELETEX_STRING
import dev.revokt.engine.walker.Want.Companion.budget
import dev.revokt.engine.walker.Want.Companion.fallbackLimit
import dev.revokt.engine.walker.Want.Companion.found
import dev.revokt.engine.walker.Want.Companion.noIssuer

/**
 * The §9 walker fixtures' decision columns, rows (a) to (aj) less (j) and (j2) ([WalkerFixturesJ]), over the rows of
 * [WalkerFixturesAToR] and [WalkerFixturesS1ToAj] (spec §9 "Walker fixtures", §5.1 decision steps 2 to 8). Each
 * function gives one [DecisionRow] per case of the row, in the row's case order. Every walk `Found` decides alike on
 * both paths (step 6 never runs); a walk `NotFound` or `Budget` within `FALLBACK_MAX_PRESENTED` runs the harness's
 * [SymPathBuilder], which fails unless the row says it finds a path; over it the fallback is skipped; and on the
 * disabled path every `FallbackNotUsed` is `DISABLED` (revision 50). Rows (x), (ab) and (ag) end before step 5.
 */
internal object WalkerDecisionRows {
    private val honestPath = arrayOf("L", "I", "R")

    private fun List<WalkerFixture>.rows(
        honest: String = "I",
        want: (WalkerFixture) -> Want,
    ): List<DecisionRow> = map { DecisionRow(it, want(it), honest = honest) }

    fun a(): List<DecisionRow> = WalkerFixturesAToR.a().rows { found(*honestPath) }

    fun b(): List<DecisionRow> = WalkerFixturesAToR.b().rows { found(*honestPath) }

    fun c(): List<DecisionRow> = WalkerFixturesAToR.c().rows { found(*honestPath) }

    /** (d): the fake's unsupported own OID is a diagnostic on a `Found`. */
    fun d(): List<DecisionRow> =
        WalkerFixturesAToR.d().rows { found(*honestPath, findings = listOf(unsupported(false))) }

    /** (e): verdict equals honest. 63 junk presents 65 certificates, so the runner checks its step-3 cut too. */
    fun e(): List<DecisionRow> = WalkerFixturesAToR.e().rows { found(*honestPath) }

    fun f(): List<DecisionRow> = WalkerFixturesAToR.f().rows { found("L", "I", "R1") }

    /** (g): walker-harness `NO_ISSUER(NO_CANDIDATE)`; the fake finds no issuer either. */
    fun g(): List<DecisionRow> = WalkerFixturesAToR.g().rows { noIssuer(NoIssuerReason.NO_CANDIDATE) }

    fun h(): List<DecisionRow> = WalkerFixturesAToR.h().rows { found(*honestPath) }

    /** (i): within the budget `Found`; one past it `Budget` over `FALLBACK_MAX_PRESENTED`, so the fallback is skipped. */
    fun i(): List<DecisionRow> =
        WalkerFixturesAToR.i().rows { f ->
            if (f.walk.kind == ExpectedWalk.Kind.FOUND) found(*honestPath) else budget(FallbackReason.SKIPPED)
        }

    fun k(): List<DecisionRow> = WalkerFixturesAToR.k().rows { found(*honestPath) }

    fun k2(): List<DecisionRow> = WalkerFixturesAToR.k2().rows { found(*honestPath) }

    fun l(): List<DecisionRow> = WalkerFixturesAToR.l().rows { found(*honestPath) }

    fun m(): List<DecisionRow> = WalkerFixturesAToR.m().rows { found(*honestPath) }

    /** (n): `outcomeDepended = false`. */
    fun n(): List<DecisionRow> =
        WalkerFixturesAToR.n().rows { found(*honestPath, findings = listOf(unsupported(false))) }

    /**
     * (o): the attacker CA first → its key alone, so not `REVOKED` when only the honest key is; the honest intermediate
     * first → its key alone, `REVOKED`.
     */
    fun o(): List<DecisionRow> {
        val (attackerFirst, honestFirst) = WalkerFixturesAToR.o()
        return listOf(
            DecisionRow(attackerFirst, found("L", "S", "R", verdict = Verdicts.OTHER_KEY)),
            DecisionRow(honestFirst, found(*honestPath)),
        )
    }

    fun p(): List<DecisionRow> = WalkerFixturesAToR.p().rows { found(*honestPath) }

    fun q(): List<DecisionRow> = WalkerFixturesAToR.q().rows("I1") { found("L", *Array(9) { n -> "I${n + 1}" }, "R") }

    /** (r): the OID mismatch carries `AlgorithmIdMismatch` for the leaf; NULL vs absent carries none. */
    fun r(): List<DecisionRow> {
        val (oid, nullAbsent) = WalkerFixturesAToR.r()
        return listOf(
            DecisionRow(oid, found(*honestPath, findings = listOf(mismatch(0)))),
            DecisionRow(nullAbsent, found(*honestPath)),
        )
    }

    /** (s1): `Found` through the honest intermediate, `REVOKED`. */
    fun s1(): List<DecisionRow> = WalkerFixturesS1ToAj.s1().rows { found(*honestPath) }

    /**
     * (s2) and (t): `Budget`, no path, fallback skipped: `Rejected` with `rule = PATH_BUDGET_EXCEEDED`, the honest key not
     * evaluated (`REVOKED ⇔ honestKey ∈ issuerSpkiSha256s`, which the runner asserts for every row).
     */
    fun s2(): List<DecisionRow> = WalkerFixturesS1ToAj.s2().rows { budget(FallbackReason.SKIPPED) }

    fun t(): List<DecisionRow> = WalkerFixturesS1ToAj.t().rows { budget(FallbackReason.SKIPPED) }

    /** (v) and (v2): generated chains, the honest key the generator's, the path the walk's. */
    fun v(): List<DecisionRow> = WalkerFixturesS1ToAj.v().rows { generatedFound() }

    fun v2(): List<DecisionRow> = WalkerFixturesS1ToAj.v2().rows { generatedFound() }

    private fun generatedFound(): Want = Want(PathStatus.FOUND, Verdicts.HONEST, path = null)

    /** (w): reported path `leaf → I → anchor`. */
    fun w(): List<DecisionRow> = WalkerFixturesS1ToAj.w().rows { found("L", "I", "R1") }

    /** (x): a self-signed anchor as the server certificate: step 2's `Found([leaf])`, keyed by its own key. */
    fun x(): List<DecisionRow> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val f = w.fixture("x", "", listOf(root), listOf(root), ExpectedWalk(ExpectedWalk.Kind.FOUND))
        return listOf(DecisionRow(f, found("R"), honest = "R", noWalk = true))
    }

    /** (y): within the budget `Found`; one past it `Budget` with the whole walk aborted, fallback skipped. */
    fun y(): List<DecisionRow> =
        WalkerFixturesS1ToAj.y().rows("I1") { f ->
            if (f.walk.kind == ExpectedWalk.Kind.FOUND) found("L", "I1", "I2", "R") else budget(FallbackReason.SKIPPED)
        }

    fun y2(): List<DecisionRow> = WalkerFixturesS1ToAj.y2().rows("I1") { found("L", "I1", "I2", "R") }

    /** (z): `NO_ISSUER(UNANCHORED)`, no `UnsupportedAlgorithm`. */
    fun z(): List<DecisionRow> = WalkerFixturesS1ToAj.z().rows { noIssuer(NoIssuerReason.UNANCHORED) }

    /** (aa): `pathsFound = 1`. */
    fun aa(): List<DecisionRow> = WalkerFixturesS1ToAj.aa().rows("R") { found("L", "R") }

    /**
     * (ab): a `PARSE_FAILED` leaf with no CRLite generation → `rules = {PARSE_FAILED, NO_DATA}`, `rule = NO_DATA`; no
     * walk, no key.
     */
    fun ab(): List<DecisionRow> {
        val h = Honest()
        val f =
            WalkerFixture(
                "ab",
                "",
                listOf(garbage(64), h.intermediate.der),
                listOf(h.root.der),
                h.w.ok,
                ExpectedWalk(ExpectedWalk.Kind.NOT_FOUND),
                label = h.w::label,
            )
        val want =
            Want(PathStatus.PARSE_FAILED, Verdicts.PARSE_FAILED_NO_DATA, PathReason.STRUCTURE)
        return listOf(DecisionRow(f, want, crlite = noGeneration(), noWalk = true))
    }

    /**
     * (ac): the walk is `NotFound(NO_CANDIDATE)`, so only the PKIX fallback reaches the honest issuer (§10 residual 1):
     * the harness fallback runs a custom delegate's canonicaliser and finds it, `REVOKED`; disabled it is
     * `NO_ISSUER(NO_CANDIDATE)`. With the related, anchored attacker CA ahead: `Found` through it alone on both paths
     * (§10 residuals 1 and 15).
     */
    fun ac(): List<DecisionRow> {
        val (plain, decoy) = WalkerFixturesS1ToAj.ac()
        return listOf(
            DecisionRow(
                plain,
                Want(
                    PathStatus.FOUND,
                    Verdicts.HONEST,
                    walkerReason = NoIssuerReason.NO_CANDIDATE,
                    usedFallback = true,
                    path = honestPath.toList(),
                ),
                disabled = noIssuer(NoIssuerReason.NO_CANDIDATE, FallbackReason.DISABLED),
                fallback = customDelegate(plain),
            ),
            DecisionRow(decoy, found("L", "S", "R", verdict = Verdicts.OTHER_KEY), fallback = customDelegate(decoy)),
        )
    }

    /**
     * (ad): `Budget` after `MAX_EXPLORED`; the fallback finds the honest path, so `PATH_BUDGET_EXCEEDED`,
     * `usedFallback = true`, the honest key alone, `rule = REVOKED`. Disabled: no key evaluated, `FallbackNotUsed
     * (DISABLED)`, `rule = PATH_BUDGET_EXCEEDED`.
     */
    fun ad(): List<DecisionRow> =
        WalkerFixturesS1ToAj.ad().map { f ->
            DecisionRow(
                f,
                Want(
                    PathStatus.PATH_BUDGET_EXCEEDED,
                    Verdicts.BUDGET_HONEST,
                    PathReason.EXPLORATION_BUDGET,
                    usedFallback = true,
                    path = honestPath.toList(),
                ),
                disabled = budget(FallbackReason.DISABLED),
                fallback = customDelegate(f),
            )
        }

    /**
     * (ae): walker `UNANCHORED`, the fallback fails: the harness reports the walker's reason directly (§5.1; the
     * `PLATFORM_ONLY` label is the trust-manager bindings', 0.3).
     */
    fun ae(): List<DecisionRow> = WalkerFixturesS1ToAj.ae().rows { noIssuer(NoIssuerReason.UNANCHORED) }

    /** (af): 9 presented, walk `UNANCHORED`: the fallback skipped, `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)`. */
    fun af(): List<DecisionRow> = WalkerFixturesS1ToAj.af().rows { fallbackLimit(NoIssuerReason.UNANCHORED) }

    /**
     * (ag): 70 presented through decide's step 3, not the harness entry: `PATH_BUDGET_EXCEEDED(EXPLORATION_BUDGET)`
     * without a walk. Step 6 branches on the walk's result, so it does not run, and the row carries no
     * `FallbackNotUsed` on either path (the maintainer's reading, 2026-11-05).
     */
    fun ag(): List<DecisionRow> =
        with(Honest()) {
            val f =
                fixture(
                    "ag",
                    presented = listOf(leaf) + junk(68) + intermediate,
                    walk = notFound(NoIssuerReason.NO_CANDIDATE),
                )
            listOf(DecisionRow(f, budget(notUsed = null), harness = false, noWalk = true))
        }

    /** (ah): `Budget` after `MAX_EXPLORED` verifications; 46 presented, so the fallback is skipped. */
    fun ah(): List<DecisionRow> = WalkerFixturesS1ToAj.ah().rows { budget(FallbackReason.SKIPPED) }

    /**
     * (ai): the 17-certificate path is `Found`; the 18-certificate one is a dead end, `UNANCHORED`, over
     * `FALLBACK_MAX_PRESENTED` presented, so `PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)`.
     */
    fun ai(): List<DecisionRow> {
        val (fits, tooDeep) = WalkerFixturesS1ToAj.ai()
        return listOf(
            DecisionRow(fits, found("L", *Array(15) { n -> "I${n + 1}" }, "R"), honest = "I1"),
            DecisionRow(tooDeep, fallbackLimit(NoIssuerReason.UNANCHORED), honest = "I1"),
        )
    }

    /**
     * (aj): neither unrelated issuer is a candidate, of the walk or of the harness fallback, which offers related
     * certificates only: the outcome is the fallback's, here failed, so `NO_ISSUER(NO_CANDIDATE)`, or `UNANCHORED` with
     * the related decoy.
     */
    fun aj(): List<DecisionRow> =
        WalkerFixturesS1ToAj.aj().map { f ->
            val reason = f.walk.reason ?: error("$f: (aj) is NotFound")
            DecisionRow(f, noIssuer(reason), honest = "U1")
        }

    /**
     * The harness fallback for (ac) and (ad) as a custom delegate builds paths: its canonicaliser reads the TeletexString
     * and UTF8String spellings of the honest issuer's name as one, as the misclassifying delegate of those rows does.
     */
    private fun customDelegate(f: WalkerFixture): () -> SymPathBuilder {
        val w = FixtureWorld()
        val teletex = w.name("Intermediate", TELETEX_STRING)
        val utf8 = w.name("Intermediate")
        val canonicaliser = { name: ByteArray -> canonicalSubject(if (name.contentEquals(teletex)) utf8 else name) }
        return { SymPathBuilder(f.ok, f.unsupported, canonicaliser) }
    }
}
