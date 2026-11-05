// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** Where the reported path came from (spec §4). Growable; M2 adds `MIXED`. */
public enum class ChainSource {
    /** A platform-verified chain, trusted without re-verification: §5.1 step 4, or `EvaluationRequest.verifiedPaths`. */
    PLATFORM,

    /** Rebuilt by revokt's walker from the presented certificates and the anchors. */
    RECONSTRUCTED,

    /** Reserved: produced by no M1 path. */
    PRESENTED,
}
