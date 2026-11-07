// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.jvm.JvmStatic

/**
 * What an [HttpFetcher] returns (spec §3): the status, the response headers and the whole decoded body. Public, not
 * testing API, since every [HttpFetcher] constructs one. The engine re-checks the body's size and hashes it. A value
 * type: equality is by content, and [body] returns a fresh copy.
 */
public class FetchResponse private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature.
    public val status: Int = requireNotNull(builder.status) { "status is not set" }

    /** The response headers as the fetcher gave them, names unchanged and in order; an unmodifiable copy. */
    public val headers: Map<String, List<String>> =
        buildMap { builder.headers.forEach { (name, values) -> put(name, buildList { addAll(values) }) } }

    internal val bodyBytes: ByteString = builder.body

    /**
     * Every value of header [name], compared ignoring case (HTTP/2 and `java.net.http` lowercase names), in the
     * order [headers] holds them.
     */
    internal fun headerValues(name: String): List<String> =
        headers.entries.filter { it.key.equals(name, ignoreCase = true) }.flatMap { it.value }

    /** The decoded body, as a fresh copy. */
    public val body: ByteArray get() = bodyBytes.toByteArray()

    /** A builder holding this response's values. */
    public fun newBuilder(): Builder = Builder().status(status).headers(headers).body(bodyBytes.toByteArray())

    override fun equals(other: Any?): Boolean =
        other is FetchResponse && status == other.status && headers == other.headers && bodyBytes == other.bodyBytes

    override fun hashCode(): Int = listOf(status, headers, bodyBytes).hashCode()

    // A body can be a whole filter: it prints as its size.
    override fun toString(): String = "FetchResponse(status=$status, headers=$headers, body=${bodyBytes.size} bytes)"

    /** Builds a [FetchResponse]; the body defaults to empty. */
    public class Builder {
        internal var status: Int? = null
            private set
        internal val headers: LinkedHashMap<String, MutableList<String>> = LinkedHashMap()
        internal var body: ByteString = ByteString.EMPTY
            private set

        public fun status(status: Int): Builder = apply { this.status = status }

        /** Adds [value] to the values of header [name]. */
        public fun header(
            name: String,
            value: String,
        ): Builder = apply { headers.getOrPut(name) { mutableListOf() }.add(value) }

        /**
         * Replaces every header with a copy of [headers]. An entry with a null name, as `HttpURLConnection.getHeaderFields`
         * gives the status line, is dropped.
         */
        public fun headers(headers: Map<String, List<String>>): Builder =
            apply {
                this.headers.clear()
                for (entry in headers.entries) {
                    // A Java map can hold a null key whatever the Kotlin type says.
                    val name: Any? = entry.key
                    if (name !is String) continue
                    this.headers[name] = entry.value.toMutableList()
                }
            }

        /** The decoded body; copied. */
        public fun body(body: ByteArray): Builder = apply { this.body = body.toByteString() }

        public fun build(): FetchResponse = FetchResponse(this)
    }

    public companion object {
        /** The response with [status], a copy of [headers] (null names dropped, as [Builder.headers]) and [body]. */
        @JvmStatic
        public fun of(
            status: Int,
            headers: Map<String, List<String>>,
            body: ByteArray,
        ): FetchResponse =
            Builder()
                .status(status)
                .headers(headers)
                .body(body)
                .build()
    }
}
