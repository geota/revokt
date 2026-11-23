// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot
import dev.revokt.RevoktInternalApi

/**
 * An anchor snapshot and the [CandidateIndex] built from it, published as one reference (spec §5.1 decision step 1),
 * so the one read per evaluation never pairs an index with another snapshot's id. `@RevoktInternalApi` so that the
 * JVM binding can hold the one its anchor snapshot build returns (spec §3.1 item 4); the index stays internal.
 */
@RevoktInternalApi
public class IndexedSnapshot internal constructor(
    public val snapshot: AnchorSnapshot,
    internal val index: CandidateIndex,
)
