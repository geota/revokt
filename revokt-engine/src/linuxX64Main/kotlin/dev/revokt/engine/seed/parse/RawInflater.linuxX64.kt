// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

// The linuxX64 purity gate only compiles (spec §3): no inflater, so a deflated seed entry is unreadable there.
internal actual fun rawInflater(): RawInflater =
    throw UnsupportedOperationException("linuxX64 has no inflater: the purity gate only compiles (spec §3)")
