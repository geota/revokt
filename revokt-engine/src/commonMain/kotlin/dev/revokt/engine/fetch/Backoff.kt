// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchResponse
import dev.revokt.RevoktLimits

/**
 * The server's `Backoff` and `Retry-After` (spec §7.1: "honour `Backoff` and `Retry-After` up to `MAX_BACKOFF` (24 h;
 * transport headers are unsigned)"), read for #131 to persist. Names are matched ignoring case through
 * [FetchResponse.headerValues] (HTTP/2 and `java.net.http` lowercase them, #177). Each value is read as delta-seconds,
 * RFC 9110 §10.2.3's `1*DIGIT` with surrounding spaces and tabs: Remote Settings (Kinto) sends both headers in seconds.
 * A value that is not one, an HTTP-date `Retry-After` included, is ignored. The longest wait of every value read wins,
 * clamped to [RevoktLimits.MAX_BACKOFF].
 */
internal object Backoff {
    private const val MILLIS_PER_SECOND = 1_000L

    /** The wait in milliseconds, at most `MAX_BACKOFF`; null when the response carries no readable value. */
    fun read(response: FetchResponse): Long? {
        var longest: Long? = null
        for (value in response.headerValues("Backoff") + response.headerValues("Retry-After")) {
            val millis = millis(value) ?: continue
            if (longest == null || millis > longest) longest = millis
        }
        return longest
    }

    /** [value] as delta-seconds in milliseconds, clamped to `MAX_BACKOFF` without overflowing; null when not one. */
    private fun millis(value: String): Long? {
        val digits = value.trim(' ', '\t')
        if (digits.isEmpty() || !digits.all { it in '0'..'9' }) return null
        val cap = RevoktLimits.MAX_BACKOFF
        var seconds = 0L
        for (c in digits) {
            seconds = seconds * 10 + (c - '0')
            if (seconds * MILLIS_PER_SECOND >= cap) return cap
        }
        return seconds * MILLIS_PER_SECOND
    }
}
