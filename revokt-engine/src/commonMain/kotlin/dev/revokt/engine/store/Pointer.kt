// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

/**
 * The `current` pointer file (spec §6.5): the generation directories [live] and [previous]. [StoreLayout.point] writes
 * one only when both name complete generations and [previous]'s trust class ranks at least [live]'s.
 */
internal data class Pointer(
    val live: String,
    val previous: String?,
) {
    init {
        require(GenerationNames.isDirectory(live)) { "'$live' is not a generation directory" }
        require(
            previous == null || GenerationNames.isDirectory(previous),
        ) { "'$previous' is not a generation directory" }
        require(previous != live) { "previous is live" }
    }
}

internal object PointerJson {
    fun write(pointer: Pointer): ByteArray =
        StoreFields.encode(
            "live" to StoreFields.string(pointer.live),
            "previous" to StoreFields.string(pointer.previous),
        )

    /** The pointer in [bytes], or null when it is malformed. */
    fun read(bytes: ByteArray): Pointer? =
        StoreFields.decodeOrNull(bytes) { f -> Pointer(f.string("live"), f.optString("previous")) }
}
