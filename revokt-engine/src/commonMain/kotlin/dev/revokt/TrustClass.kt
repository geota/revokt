// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * How a generation was obtained, ranked (spec §4). Growable: the `UNSIGNED_DATA` floor compares [rank], never
 * `ordinal`, so a value can be inserted later.
 */
public enum class TrustClass(
    public val rank: Int,
) {
    SIGNED(300),
    MIRROR(200),
    SYSTEM(150),
    BUNDLED(100),
}
