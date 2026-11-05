// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

// The linuxX64 purity gate only compiles (spec §3): an empty stub, so matching there would be raw bytes and SKI only.
@Suppress("UNUSED_PARAMETER") // the expect's signature; the stub reads nothing
internal actual fun canonicalSubject(nameDer: ByteArray): String? = null
