// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.detekt

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/** The repository's structural rules (CONTRIBUTING §3). Every message says what to do, not only what is wrong. */
class RevoktRuleSetProvider : RuleSetProvider {
    override val ruleSetId: String = "revokt"

    override fun instance(config: Config): RuleSet =
        RuleSet(
            ruleSetId,
            listOf(
                PublicConstructorOnFinalClass(config),
                NoDataOrValueClassOnPublicSurface(config),
                ClubcardPortRules(config),
                NoHttpClientInTests(config),
            ),
        )
}
