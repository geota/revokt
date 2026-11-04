// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import java.lang.management.ManagementFactory

/**
 * Spec §6.5's JSON allocation budget (#99) and its measurement protocol, shared by [JsonAllocationTest] and
 * [JsonFuzzTest]: HotSpot's per-thread allocation counter, after one warm-up decode on the same thread of §6.5's
 * example document and of one rejected input (the error path loads classes of its own: the error enum, the message's
 * string concatenation), so that per-process class loading does not count.
 */
internal object JsonBudget {
    /** §6.5's example: exponents, negative and beyond-`Long` numbers, multi-byte UTF-8, `\u` escapes with a pair. */
    const val WARM_UP = "{\"a\":[0,-1.5e3,18446744073709551616,\"é😀\\u00e9\\ud83d\\ude00\",true,false,null,{}]}"

    /** The counter, or null where the JVM does not provide it (the budget is then not checked). */
    private val threads: com.sun.management.ThreadMXBean? =
        (ManagementFactory.getThreadMXBean() as? com.sun.management.ThreadMXBean)
            ?.takeIf { it.isThreadAllocatedMemorySupported && it.isThreadAllocatedMemoryEnabled }

    val supported: Boolean get() = threads != null

    /** The warm-up decodes; once per thread is enough, repeating them is harmless. */
    fun warmUp() {
        Json.parse(WARM_UP.encodeToByteArray())
        try {
            Json.parse("[".encodeToByteArray())
        } catch (_: JsonParseException) {
            // Expected: the rejection only loads the error path.
        }
    }

    /** The bound for [len] input bytes: 4·len + 64 KiB for Remote Settings data, 20·len + 64 KiB for any input. */
    fun bound(
        factor: Int,
        len: Int,
    ): Long = factor.toLong() * len + 64 * 1024

    /** The bytes this thread allocates running [block], or -1 without a counter. */
    inline fun <T> allocated(block: () -> T): Pair<T, Long> {
        val before = current()
        val result = block()
        return result to (if (before < 0) -1 else current() - before)
    }

    fun current(): Long = threads?.currentThreadAllocatedBytes ?: -1
}
