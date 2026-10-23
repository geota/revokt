// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of clubcard 0.3.4 src/clubcard.rs (git ecca8d1a9e92f9f3b4b910c05fe11c190836501e), spec §3.1.
// `Display` and `ApproximateSizeOf` (Firefox memory reporting) are not translated.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi
import okio.ByteString

/** The result of a checked membership query. */
@RevoktInternalApi
public enum class Membership {
    MEMBER,
    NONMEMBER,
    NOT_IN_UNIVERSE,
    NO_DATA,
    ;

    @RevoktInternalApi
    public companion object {
        /** `From<bool>`: `true` is [MEMBER]. */
        public fun of(member: Boolean): Membership = if (member) MEMBER else NONMEMBER
    }
}

/**
 * Metadata needed to compute membership in a clubcard. `usize` fields are `Long` (the v4 encoding writes them as
 * `u32`, so sums with a row number cannot overflow); the rank is an `Int` (a `u8` in v4).
 */
@RevoktInternalApi
public class ClubcardIndexEntry(
    /** Description of the hash function h. */
    public val approxFilterM: Long,
    /** Description of the hash function g. */
    public val exactFilterM: Long,
    /** The number of columns in X. */
    public val approxFilterRank: Int,
    /** An offset t such that `[0^t || h(u)] * X = h(u) * Xi`, where i is the block identifier. */
    public val approxFilterOffset: Long,
    /** An offset t such that `[0^t || g(u)] * Y = g(u) * Yi`, where i is the block identifier. */
    public val exactFilterOffset: Long,
    /** Whether to invert the output of queries to this block. */
    public val inverted: Boolean,
    /** A list of elements of `Ui \ Ri` that are not correctly encoded by this block. */
    public val exceptions: List<ByteString>,
) {
    override fun toString(): String =
        "ClubcardIndexEntry(approxFilterM=$approxFilterM, exactFilterM=$exactFilterM, " +
            "approxFilterRank=$approxFilterRank, approxFilterOffset=$approxFilterOffset, " +
            "exactFilterOffset=$exactFilterOffset, inverted=$inverted, exceptions=${exceptions.size})"
}

/** Lookup table from block identifiers to block metadata (`BTreeMap<Vec<u8>, ClubcardIndexEntry>` upstream). */
@RevoktInternalApi
public typealias ClubcardIndex = Map<ByteString, ClubcardIndexEntry>

/**
 * A queryable Clubcard. [U] is the metadata for determining whether a [Queryable] is in the encoded universe; the
 * partition metadata is `Unit` for CRLite and is not modelled. Columns are `LongArray`s; revokt's decoders append one
 * zero pad word to each (spec §6.4), which [Equation.eval] never depends on.
 */
@RevoktInternalApi
public class Clubcard<U>(
    /** Metadata for determining whether a Queryable is in the encoded universe. */
    public val universe: U,
    /** Lookup table for per-block metadata. */
    public val index: ClubcardIndex,
    /** The matrix X. */
    public val approxFilter: Array<LongArray>,
    /** The matrix Y. */
    public val exactFilter: LongArray,
) {
    /**
     * Perform a membership query without checking whether the item is in the universe. The result is undefined if
     * the item is not in the universe, and if the universe's `AsQuery` differs from the item's.
     */
    public fun uncheckedContains(item: Queryable<U>): Boolean {
        val meta = index[item.block()] ?: return false
        return membershipOf(item, meta) xor meta.inverted
    }

    private fun membershipOf(
        item: Queryable<U>,
        meta: ClubcardIndexEntry,
    ): Boolean {
        // All queries evaluate to 0 on an empty filter, but logically such a filter does not include anything, so
        // it is handled as a special case.
        if (meta.approxFilterM == 0L) return false

        // Check if h(item) * X is 0.
        val approxQuery = item.asApproxQuery(meta)
        for (i in 0 until meta.approxFilterRank) {
            if (approxQuery.eval(approxFilter[i]) != 0) return false
        }

        // Check if g(item) * Y is 0.
        val exactQuery = item.asExactQuery(meta)
        if (exactQuery.eval(exactFilter) != 0) return false

        val discriminant = item.discriminant()
        for (exception in meta.exceptions) {
            if (exception == discriminant) return false
        }
        return true
    }

    /** Check that the item is in the appropriate universe, and then perform a membership query. */
    public fun contains(item: Queryable<U>): Membership {
        if (!item.inUniverse(universe)) return Membership.NOT_IN_UNIVERSE
        if (!index.containsKey(item.block())) return Membership.NO_DATA
        return Membership.of(uncheckedContains(item))
    }
}
