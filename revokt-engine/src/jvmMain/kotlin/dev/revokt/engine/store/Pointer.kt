// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

/**
 * The `current` pointer file (spec §6.5): the names of the generation files [live] and [previous], each 64 lowercase
 * hex characters. A damaged name fails the strict read or names a key no stored file hashes to, so the pointer needs no
 * checksum of its own.
 */
internal data class Pointer(
    val live: String,
    val previous: String?,
) {
    init {
        require(GenerationNames.isSha256Hex(live)) { "'$live' is not a generation file name" }
        require(
            previous == null || GenerationNames.isSha256Hex(previous),
        ) { "'$previous' is not a generation file name" }
        require(previous != live) { "previous is live" }
    }
}

internal object PointerJson {
    fun write(pointer: Pointer): ByteArray =
        StoreFields.encode(
            "live" to StoreFields.string(pointer.live),
            "previous" to StoreFields.string(pointer.previous),
        )

    /**
     * The pointer in [bytes], or null when it is malformed: not a JSON object of `live` and an optional `previous`, with
     * no other member and none twice (#246). Read strictly, since only this engine writes it and a member name damaged
     * into one a lenient reader skips would read as a pointer that no longer names its `previous`, which prune would
     * then delete; `Malformed` deletes nothing and takes the heal path instead (#236, #242).
     */
    fun read(bytes: ByteArray): Pointer? =
        StoreFields.decodeOrNull(bytes) { f ->
            f.only("live", "previous")
            Pointer(f.string("live"), f.optString("previous"))
        }
}
