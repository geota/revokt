// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Evaluates one [EvaluationRequest] outside any trust manager (spec §4): the decision list of §5.1 over the request's
 * chain or verified paths, returning the [Verdict]. Sealed, so a consumer never implements it and members can be added;
 * its single implementation lives beside it and is what `Revokt.evaluator` returns (§3).
 */
public sealed interface Evaluator {
    public fun evaluate(request: EvaluationRequest): Verdict
}
