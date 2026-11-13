// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.PathBuilderFallback
import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import okio.ByteString

/**
 * The [DecideContext] inputs that outlive one evaluation: the [verifier], its startup [probe], the [crossCallMemo]
 * every walk shares, and step 6's [fallback], null when it is disabled (`pkixFallback(false)`).
 */
internal class DecideInputs(
    val verifier: SignatureVerifier,
    val probe: Set<String>,
    val crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>,
    val fallback: PathBuilderFallback?,
) {
    /** The context of one decision at [nowMillis], with or without step 6's `PLATFORM_ONLY` promotion. */
    fun at(
        nowMillis: Long,
        platformOnly: Boolean,
    ): DecideContext = DecideContext(verifier, probe, crossCallMemo, fallback, nowMillis, platformOnly)
}
