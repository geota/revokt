// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** Where the reported path came from (spec §4). Growable; M2 adds `MIXED`. Every M1 chain is [RECONSTRUCTED]. */
public enum class ChainSource {
    /** The platform's verified chain (spec §5.1 step 4). */
    PLATFORM,

    /** Rebuilt by revokt's walker from the presented certificates and the anchors. */
    RECONSTRUCTED,

    /** Reserved: produced by no M1 path. */
    PRESENTED,
}
