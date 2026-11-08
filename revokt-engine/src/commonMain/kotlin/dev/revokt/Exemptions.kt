// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:JvmName("Exemptions")

package dev.revokt

import dev.revokt.engine.walker.isFatal
import kotlin.jvm.JvmName

/**
 * Exempt when both this exemption and [other] exempt (spec §4). Follows CEL's `&&` (commutative, errors absorbed when
 * the other side decides): this exemption runs first, and when it answers false the result is false and [other] does
 * not run; when [other] answers false the result is false even if this one threw; both true is true. Otherwise (one
 * threw and the other answered true, or both threw) the first throw propagates, and the evaluation records it as not
 * exempt plus a `Finding.EngineError` whose producer is `EXEMPTION`. An absorbed throw is not recorded, so the outcome
 * and the findings never depend on the operand order. A fatal error (§5.5's catch rule) always propagates at once.
 * Java: `Exemptions.and(a, b)`.
 */
public infix fun Exemption.and(other: Exemption): Exemption = combined(this, other, decisive = false)

/**
 * Exempt when this exemption or [other] exempts (spec §4). Follows CEL's `||` (commutative, errors absorbed when the
 * other side decides): when this exemption answers true the result is true and [other] does not run; when [other]
 * answers true the result is true even if this one threw; both false is false. Otherwise the first throw propagates,
 * as for [and]. Java: `Exemptions.or(a, b)`.
 */
public infix fun Exemption.or(other: Exemption): Exemption = combined(this, other, decisive = true)

/**
 * CEL's `&&` ([decisive] false) or `||` ([decisive] true): either operand answering [decisive] decides, absorbing a
 * throw from the other; with no decisive answer, the first throw propagates, else the result is `!decisive`.
 */
private fun combined(
    first: Exemption,
    second: Exemption,
    decisive: Boolean,
): Exemption =
    Exemption { context ->
        val a = first.attempt(context)
        if (a.getOrNull() == decisive) return@Exemption decisive
        val b = second.attempt(context)
        if (b.getOrNull() == decisive) return@Exemption decisive
        a.exceptionOrNull()?.let { throw it }
        b.exceptionOrNull()?.let { throw it }
        !decisive
    }

/** [Exemption.isExempt] with a non-fatal throw caught into the result; a fatal one propagates. */
private fun Exemption.attempt(context: ExemptionContext): Result<Boolean> =
    runCatching { isExempt(context) }.onFailure { if (isFatal(it)) throw it }
