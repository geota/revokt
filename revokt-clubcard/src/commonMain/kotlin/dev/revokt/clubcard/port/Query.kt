// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of clubcard 0.3.4 src/query.rs (git ecca8d1a9e92f9f3b4b910c05fe11c190836501e), spec §3.1.
// `Filterable` is builder-only and not translated (query and decoding only, spec §3).
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi
import okio.ByteString

/** An item that hashes to a query equation (`AsQuery<W>` upstream). */
@RevoktInternalApi
public interface AsQuery {
    /**
     * Hash this item to a homogeneous equation `(s, a)` such that (1) `s` is uniform in `{0, 1, ..., m-1}`, and
     * (2) `a` satisfies the alignment requirement (`a[0] & 1 == 1`) but is otherwise uniformly random.
     */
    public fun asQuery(m: Long): Equation

    /** The block that this item belongs in. */
    public fun block(): ByteString

    /**
     * A unique identifier for this item. If this item cannot be inserted into the linear system, then its status is
     * stored in a secondary retrieval mechanism keyed by `discriminant()`.
     */
    public fun discriminant(): ByteString

    /** The query against the approximate filter: `asQuery(meta.approxFilterM)` shifted by `meta.approxFilterOffset`. */
    public fun asApproxQuery(meta: ClubcardIndexEntry): Equation =
        asQuery(meta.approxFilterM).apply { s += meta.approxFilterOffset }

    /** The query against the exact filter: `asQuery(meta.exactFilterM)` shifted by `meta.exactFilterOffset`. */
    public fun asExactQuery(meta: ClubcardIndexEntry): Equation =
        asQuery(meta.exactFilterM).apply { s += meta.exactFilterOffset }
}

/**
 * An item that can be passed to [Clubcard.contains] (`Queryable<W>` upstream). [U] is the universe metadata stored in
 * the clubcard and passed to [inUniverse] before a query is performed; the query runs only if it returns true. The
 * partition metadata (`PartitionMetadata` upstream) is `Unit` for CRLite and is not modelled.
 */
@RevoktInternalApi
public interface Queryable<U> : AsQuery {
    public fun inUniverse(meta: U): Boolean
}
