// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The platform's canonical form of a DER `Name` (spec §3), the canonical half of the walker's relatedness test (§5.1
 * deferral rule): on the JVM and Android `X500Principal(nameDer).getName(CANONICAL)`. Null when the platform cannot
 * read the name; the walker then matches by raw bytes and SKI only. The public seam is `PlatformTrust.canonicalSubject`.
 */
internal expect fun canonicalSubject(nameDer: ByteArray): String?
