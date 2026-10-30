// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The layer that produces a rule (spec §4). Growable: M2 adds `ONECRL`, `CRLSET` and `DENYLIST` (L1/L2), M3 `CT` (L4),
 * M4 `DISTRUST` (L5).
 */
public enum class Layer {
    PATH,
    CRLITE,
}
