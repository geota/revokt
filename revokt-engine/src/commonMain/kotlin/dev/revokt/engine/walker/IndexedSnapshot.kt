// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot

/**
 * An anchor snapshot and the [CandidateIndex] built from it, published as one reference (spec §5.1 decision step 1),
 * so the one read per evaluation never pairs an index with another snapshot's id.
 */
internal class IndexedSnapshot(
    val snapshot: AnchorSnapshot,
    val index: CandidateIndex,
)
