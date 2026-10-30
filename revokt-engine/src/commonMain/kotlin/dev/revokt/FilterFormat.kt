// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** The CRLite filter encoding of a generation (spec §3.2): the bincode v3 Mozilla serves, or C2SP's v4. Growable. */
public enum class FilterFormat {
    V3,
    V4,
}
