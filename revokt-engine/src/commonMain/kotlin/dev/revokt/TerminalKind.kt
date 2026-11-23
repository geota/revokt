// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** What the reported path ends in (spec §4, §5.1 invariant), on the evaluation's `DEBUG` line. Growable; M2 adds `PRELOAD`. */
internal enum class TerminalKind {
    ANCHOR,
}
