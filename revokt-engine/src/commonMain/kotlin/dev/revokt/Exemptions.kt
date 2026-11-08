// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:JvmName("Exemptions")

package dev.revokt

import kotlin.jvm.JvmName

/**
 * Exempt when both this exemption and [other] exempt (spec §4). Both always run, so the combination stays a pure
 * function of the context whichever operand comes first, and a throw in either operand propagates: the evaluation
 * records it as not exempt plus a `Finding.EngineError` whose producer is `EXEMPTION`. Java: `Exemptions.and(a, b)`.
 */
public infix fun Exemption.and(other: Exemption): Exemption {
    val first = this
    return Exemption { context -> first.isExempt(context) and other.isExempt(context) }
}

/**
 * Exempt when this exemption or [other] exempts (spec §4). Both always run, so a throw in either operand propagates,
 * as for [and]. Java: `Exemptions.or(a, b)`.
 */
public infix fun Exemption.or(other: Exemption): Exemption {
    val first = this
    return Exemption { context -> first.isExempt(context) or other.isExempt(context) }
}
