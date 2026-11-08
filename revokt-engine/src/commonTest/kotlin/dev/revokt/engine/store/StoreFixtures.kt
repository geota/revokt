// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.RevoktStorage
import dev.revokt.TrustClass
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** Hand-built store content for the layout tests. */
internal object StoreFixtures {
    private val log: ByteString = ByteArray(32) { 0x0A }.toByteString()

    fun sha256(bytes: ByteArray): ByteString = bytes.toByteString().sha256()

    /** An `index.bin` naming [names], each with one log window. */
    fun index(vararg names: String): ByteArray =
        C2spIndex.write(
            C2spIndex.index(
                names.mapIndexed { i, n ->
                    n to
                        mapOf(log to Window(i.toULong(), i.toULong() + 10u))
                },
            ),
        )

    fun meta(
        trustClass: TrustClass = TrustClass.SIGNED,
        generationId: String = "g1",
        sourceTimestampMillis: Long = 1_762_430_400_000,
        blobs: Map<String, ByteString> = emptyMap(),
        channel: CrliteChannel = CrliteChannel.COMPAT,
    ): GenerationMeta =
        GenerationMeta(
            dataset = Dataset.CRLITE,
            channel = channel,
            trustClass = trustClass,
            generationId = generationId,
            format = FilterFormat.V3,
            freshness =
                if (trustClass ==
                    TrustClass.MIRROR
                ) {
                    Freshness.MANIFEST_LAST_MODIFIED
                } else {
                    Freshness.RECORD_LAST_MODIFIED
                },
            sourceTimestampMillis = sourceTimestampMillis,
            collection = if (trustClass == TrustClass.MIRROR) null else "security-state/cert-revocations",
            blobs = blobs,
            signed =
                if (trustClass == TrustClass.SIGNED) {
                    SignedMeta(
                        sourceTimestampMillis + 1,
                        ByteArray(32) { 7 }.toByteString(),
                        ByteArray(96) { 9 }.toByteString(),
                    )
                } else {
                    null
                },
        )

    /** A storage that records every write and delete, in order, over an in-memory one. */
    class Recording(
        private val inner: RevoktStorage = RevoktStorage.inMemory(),
    ) : RevoktStorage by inner {
        val writes = mutableListOf<String>()
        val deletes = mutableListOf<String>()

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            inner.write(name, bytes)
            writes += name
        }

        override fun delete(name: String) {
            inner.delete(name)
            deletes += name
        }
    }
}
