// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import javax.security.auth.x500.X500Principal

// X500Principal wraps every decoding failure in IllegalArgumentException, and getName(CANONICAL) throws the same when
// an attribute value does not convert: both are "no canonical form" (spec §3, §5.1 "Caches": canonicalSubject is total).
internal actual fun canonicalSubject(nameDer: ByteArray): String? =
    try {
        X500Principal(nameDer).getName(X500Principal.CANONICAL)
    } catch (_: IllegalArgumentException) {
        null
    }
