// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * host' (spec §5.1 flow step 2): [host] with ASCII `A`–`Z` folded to lowercase and one trailing dot stripped. The one
 * normalisation revokt applies to a host: `ExemptionContext.host` is filled with it, and `Exemption.hostIn` and
 * `hostSuffixIn` apply it to their configured entries, so both sides agree. Case folding is ASCII-only, never Unicode
 * (the Kelvin sign U+212A stays as it is, rather than becoming `k`), and it strips exactly one dot, so it is not
 * idempotent: apply it once, to the host as given.
 */
internal fun hostPrime(host: String): String {
    val folded = buildString(host.length) { host.forEach { append(if (it in 'A'..'Z') it + ('a' - 'A') else it) } }
    return folded.removeSuffix(".")
}

/** [hostPrime] of [host], with an empty result treated as no host. */
internal fun normalisedHost(host: String?): String? = host?.let(::hostPrime)?.ifEmpty { null }
