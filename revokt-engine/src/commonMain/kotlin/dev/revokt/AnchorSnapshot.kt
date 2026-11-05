// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * The trust anchors one trust manager walks against, read once (spec §4, §5.1 "Anchor snapshot"). A handshake reads the
 * current snapshot once and reports its [id] as `Finding.Path.anchorSnapshotId`. A value type: equality is by content,
 * and `ByteArray` getters return fresh copies. The snapshot also keeps the platform's own encodings of the anchors
 * (`getEncoded()`), which the PKIX fallback re-parses (§5.1 "PKIX fallback contract").
 */
@OptIn(RevoktTestingApi::class)
public class AnchorSnapshot private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).

    /** A process-local counter, like the generation epoch; not stable across processes. */
    public val id: Long = requireNotNull(builder.id) { "id is not set" }

    private val digest: ByteString = requireNotNull(builder.sha256) { "sha256 is not set" }

    private val anchorDers: List<ByteString> = builder.anchors

    public val createdMillis: Long = requireNotNull(builder.createdMillis) { "createdMillis is not set" }

    /** Null in M1; M2: the `INTERMEDIATES` generation the candidate index holds. */
    public val preloadGenerationId: String? = builder.preloadGenerationId

    /**
     * The platform's encoding of each anchor, in [anchors] order, for the PKIX fallback; the bytes read unless the
     * snapshot's builder set them. Not part of equality: [sha256] and [anchors] already identify the same anchors.
     * Exactly one per anchor: a caller that drops an anchor drops its encoding too.
     */
    internal val platformEncodings: List<ByteString> = builder.platformEncodings ?: anchorDers

    init {
        require(platformEncodings.size == anchorDers.size) {
            "one platform encoding per anchor: ${anchorDers.size} anchors, ${platformEncodings.size} encodings"
        }
    }

    /** The SHA-256 of the sorted anchor DERs as read (§5.3); stable across processes. A fresh copy. */
    public val sha256: ByteArray get() = digest.toByteArray()

    /** Each anchor's bytes as read (§5.3). Fresh copies. */
    public val anchors: List<ByteArray> get() = anchorDers.map { it.toByteArray() }

    /** A builder holding this snapshot's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .id(id)
            .sha256(digest.toByteArray())
            .anchors(anchors)
            .createdMillis(createdMillis)
            .preloadGenerationId(preloadGenerationId)
            .platformEncodings(platformEncodings.map { it.toByteArray() })

    override fun equals(other: Any?): Boolean =
        other is AnchorSnapshot &&
            id == other.id &&
            digest == other.digest &&
            anchorDers == other.anchorDers &&
            createdMillis == other.createdMillis &&
            preloadGenerationId == other.preloadGenerationId

    override fun hashCode(): Int = listOf(id, digest, anchorDers, createdMillis, preloadGenerationId).hashCode()

    // An anchor prints as the SHA-256 of its DER: a snapshot holds a whole trust store.
    override fun toString(): String =
        "AnchorSnapshot(id=$id, sha256=${digest.hex()}, anchors=${anchorDers.map { it.sha256().hex() }}, " +
            "createdMillis=$createdMillis, preloadGenerationId=$preloadGenerationId)"

    /** Builds an [AnchorSnapshot] for tests and fakes. */
    @RevoktTestingApi
    public class Builder {
        internal var id: Long? = null
            private set
        internal var sha256: ByteString? = null
            private set
        internal var anchors: List<ByteString> = emptyList()
            private set
        internal var createdMillis: Long? = null
            private set
        internal var preloadGenerationId: String? = null
            private set
        internal var platformEncodings: List<ByteString>? = null
            private set

        public fun id(id: Long): Builder = apply { this.id = id }

        public fun sha256(sha256: ByteArray): Builder = apply { this.sha256 = sha256.toByteString() }

        /** Replaces the anchors with copies of [ders], and drops any platform encodings, which were of the old ones. */
        public fun anchors(ders: List<ByteArray>): Builder =
            apply {
                anchors = ders.map { it.toByteString() }
                platformEncodings = null
            }

        public fun createdMillis(millis: Long): Builder = apply { createdMillis = millis }

        public fun preloadGenerationId(id: String?): Builder = apply { preloadGenerationId = id }

        /** The platform's encoding (`getEncoded()`) of each anchor, in [anchors] order; set after [anchors]. */
        internal fun platformEncodings(encodings: List<ByteArray>): Builder =
            apply { platformEncodings = encodings.map { it.toByteString() } }

        public fun build(): AnchorSnapshot = AnchorSnapshot(this)
    }
}
