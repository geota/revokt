// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a [SignatureVerifier] answers for one link (spec §3). Closed. `UNSUPPORTED` is decided by the startup probe
 * ([SignatureVerifier.unsupportedOids]), never by a server-chosen exception; the walker never trusts such a link.
 */
public enum class VerifyResult {
    VERIFIED,
    INVALID,
    UNSUPPORTED,
}
