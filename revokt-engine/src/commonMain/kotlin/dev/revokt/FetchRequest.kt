// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * One request the engine hands an [HttpFetcher] (spec §3). The engine sets the headers (`User-Agent`, and
 * `If-None-Match` as the quoted verified cursor, never an echoed server ETag) and never sends `Accept-Encoding`. A
 * value type: equality is by content. The builder is testing API, so fetcher tests can construct requests.
 */
@OptIn(RevoktTestingApi::class)
public class FetchRequest private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature.
    public val url: String = requireNotNull(builder.url) { "url is not set" }

    /** The request headers, in the order set; an unmodifiable copy. */
    public val headers: Map<String, String> = buildMap { putAll(builder.headers) }

    /**
     * The decoded body's cap: `min(attachment.size, MAX_FILTER_BYTES)` for a signed body, else the kind's `RevoktLimits`
     * cap. The fetcher stops at it while inflating and throws.
     */
    public val maxBodyBytes: Long = requireNotNull(builder.maxBodyBytes) { "maxBodyBytes is not set" }

    /** The fetch deadline, enforced by the engine; default [RevoktLimits.FETCH_TIMEOUT]. */
    public val timeoutMillis: Long = builder.timeoutMillis

    init {
        require(maxBodyBytes >= 0) { "maxBodyBytes must not be negative, got $maxBodyBytes" }
        require(timeoutMillis > 0) { "timeoutMillis must be positive, got $timeoutMillis" }
    }

    /** A builder holding this request's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .url(url)
            .headers(headers)
            .maxBodyBytes(maxBodyBytes)
            .timeoutMillis(timeoutMillis)

    override fun equals(other: Any?): Boolean =
        other is FetchRequest &&
            url == other.url &&
            headers == other.headers &&
            maxBodyBytes == other.maxBodyBytes &&
            timeoutMillis == other.timeoutMillis

    override fun hashCode(): Int = listOf(url, headers, maxBodyBytes, timeoutMillis).hashCode()

    override fun toString(): String =
        "FetchRequest(url=$url, headers=$headers, maxBodyBytes=$maxBodyBytes, timeoutMillis=$timeoutMillis)"

    /** Builds a [FetchRequest] for tests and fakes. */
    @RevoktTestingApi
    public class Builder {
        internal var url: String? = null
            private set
        internal val headers: LinkedHashMap<String, String> = LinkedHashMap()
        internal var maxBodyBytes: Long? = null
            private set
        internal var timeoutMillis: Long = RevoktLimits.FETCH_TIMEOUT
            private set

        public fun url(url: String): Builder = apply { this.url = url }

        /** Sets one header, replacing an earlier value under the same name. */
        public fun header(
            name: String,
            value: String,
        ): Builder = apply { headers[name] = value }

        /** Replaces every header with a copy of [headers]. */
        public fun headers(headers: Map<String, String>): Builder =
            apply {
                this.headers.clear()
                this.headers.putAll(headers)
            }

        public fun maxBodyBytes(bytes: Long): Builder = apply { maxBodyBytes = bytes }

        public fun timeoutMillis(millis: Long): Builder = apply { timeoutMillis = millis }

        public fun build(): FetchRequest = FetchRequest(this)
    }
}
