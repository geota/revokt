// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.jvm.JvmStatic

/**
 * Lifts one fired `REJECT` rule (spec §4, §8 exemptions). An exemption runs after policy mapping, for fired `REJECT`
 * rules on exemptable rules only, and its answer is cached with the verdict, so it must be pure: a deterministic,
 * synchronous function of its [ExemptionContext]. A throw counts as not exempt and adds a `Finding.EngineError` whose
 * producer is `EXEMPTION`.
 */
public fun interface Exemption {
    public fun isExempt(context: ExemptionContext): Boolean

    /**
     * The shipped helpers (§4), for the enterprise-CA case without a hand-written lambda. They live in this commonMain
     * file because a companion cannot straddle source sets.
     */
    public companion object {
        /**
         * Exempt when the reported path's anchor is one of [sha256s] (each the SHA-256 of an anchor's DER as revokt
         * reads it, §5.3), compared by content. [sha256s] is copied when the exemption is made, so a later change to an
         * array does not change what matches. A null `context.path.anchorSha256`, an empty reported path, never
         * matches.
         */
        @JvmStatic
        public fun anchorIn(sha256s: Collection<ByteArray>): Exemption {
            val anchors: Set<ByteString> = buildSet { sha256s.forEach { add(it.toByteString()) } }
            return Exemption { context -> context.path.anchorSha256?.toByteString() in anchors }
        }
    }
}
