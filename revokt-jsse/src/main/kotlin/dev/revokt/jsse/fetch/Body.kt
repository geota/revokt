// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.PushbackInputStream
import java.util.zip.GZIPInputStream

/** Throws `InterruptedIOException` when this thread is interrupted, leaving the flag set (spec §3 `HttpFetcher`). */
internal fun throwIfInterrupted() {
    if (Thread.currentThread().isInterrupted) throw InterruptedIOException("fetch interrupted")
}

/**
 * Reads [stream] (null: no body) whole, inflated when [rawHeaders] say `Content-Encoding: gzip`, and closes it. Returns
 * the body and the headers to report: after inflating, `Content-Encoding` and `Content-Length` describe bytes the
 * caller never sees, so they are dropped. An absent or `identity` encoding is read as is; any other throws, since the
 * fetcher asked for gzip only. Throws [BodyOverCapException] past [maxBodyBytes] decoded bytes, having read at most
 * one byte more than that from the decoder.
 */
internal fun decodedBody(
    stream: InputStream?,
    rawHeaders: Map<String?, List<String>>,
    maxBodyBytes: Long,
): Pair<ByteArray, Map<String, List<String>>> {
    // HttpURLConnection reports the status line under a null name.
    val headers = LinkedHashMap<String, List<String>>()
    for ((name, values) in rawHeaders) if (name != null) headers[name] = values
    if (stream == null) return ByteArray(0) to headers
    stream.use { raw ->
        val encodings =
            headers.entries
                .filter { (name, _) -> name.equals("Content-Encoding", ignoreCase = true) }
                .flatMap { (_, values) -> values.flatMap { it.split(',') } }
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() && it != "identity" }
        return when {
            encodings.isEmpty() -> {
                readCapped(raw, maxBodyBytes) to headers
            }

            encodings == listOf("gzip") || encodings == listOf("x-gzip") -> {
                val decoded = gunzip(raw).use { readCapped(it, maxBodyBytes) }
                decoded to
                    headers.filterKeys {
                        !it.equals("Content-Encoding", ignoreCase = true) &&
                            !it.equals("Content-Length", ignoreCase = true)
                    }
            }

            else -> {
                throw IOException("unsupported Content-Encoding $encodings: the fetcher asks for gzip only")
            }
        }
    }
}

/** A gzip decoder over [raw]; an empty body (a 304 or 204 that names gzip) decodes to nothing. */
private fun gunzip(raw: InputStream): InputStream {
    val peek = PushbackInputStream(raw, 1)
    val first = peek.read()
    if (first < 0) return ByteArrayInputStream(ByteArray(0))
    peek.unread(first)
    return GZIPInputStream(peek)
}

/**
 * Reads [input] to its end, throwing [BodyOverCapException] once it yields more than [maxBodyBytes] bytes. It never
 * asks [input] for more than one byte past the cap, and never buffers more than the cap: the gzip bomb rule (spec §3
 * `FetchResponse`, "stops at maxBodyBytes while inflating and throws"). Checks for an interrupt before each read.
 */
internal fun readCapped(
    input: InputStream,
    maxBodyBytes: Long,
): ByteArray {
    // A ByteArray holds at most Int.MAX_VALUE - 8 bytes on HotSpot; a larger cap is that.
    val cap = minOf(maxBodyBytes, MAX_ARRAY.toLong())
    val out = ByteArrayOutputStream(minOf(cap, INITIAL.toLong()).toInt())
    val buffer = ByteArray(CHUNK)
    var total = 0L
    while (true) {
        throwIfInterrupted()
        // One byte past the cap is enough to know the body is over it.
        val want = minOf(buffer.size.toLong(), cap - total + 1).toInt()
        val n = input.read(buffer, 0, want)
        if (n < 0) return out.toByteArray()
        if (total + n > cap) throw BodyOverCapException(maxBodyBytes)
        out.write(buffer, 0, n)
        total += n
    }
}

private const val CHUNK = 8192
private const val INITIAL = 64 * 1024
private const val MAX_ARRAY = Int.MAX_VALUE - 8
