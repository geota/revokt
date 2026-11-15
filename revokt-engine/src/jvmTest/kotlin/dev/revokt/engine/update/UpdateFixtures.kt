// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.ClubcardCorpus
import dev.revokt.CrliteChannel
import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.GenerationFiles
import dev.revokt.KotlinRevocationEngine
import dev.revokt.LogLevel
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLogger
import dev.revokt.TrustClass
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.SignedMeta
import dev.revokt.engine.store.StoreLayout
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** Records, filters, engines and loggers for the install tests (#130). */
internal object UpdateFixtures {
    const val FULL_PATH = "compat-full/20261017-1-compat.filter"
    const val DELTA_PATH = "compat-delta/20261021-1-compat.filter.delta"

    /**
     * One Remote Settings record per `corpus/clubcard` compat filter, synthesised from its `record.json` `source`
     * (channel, incremental, effectiveTimestamp) with a filename and id chosen here: the corpus holds filters, not
     * records (the plan review).
     */
    val fullRecord =
        FilterRecord(
            "5cc04cc0-2229-4273-bdd3-be095a8f0468",
            "compat",
            false,
            1_792_241_654_000,
            "20261017-1-compat.filter",
        )
    val deltaRecord =
        FilterRecord(
            "dc62e538-927e-4179-ac2b-02f4d7ce8361",
            "compat",
            true,
            1_792_587_524_000,
            "20261021-1-compat.filter.delta",
        )

    val bodies: Map<String, ByteArray> by lazy {
        mapOf(
            fullRecord.filename to ClubcardCorpus.file(FULL_PATH).readBytes(),
            deltaRecord.filename to ClubcardCorpus.file(DELTA_PATH).readBytes(),
        )
    }

    /** [buildIndex] over [records], reading bodies from [bodies] by attachment filename. */
    fun build(
        records: List<FilterRecord>,
        bodies: Map<String, ByteArray> = this.bodies,
        channel: CrliteChannel = CrliteChannel.COMPAT,
    ): IndexBuild = buildIndex(records, channel) { bodies.getValue(it.filename) }

    fun built(
        records: List<FilterRecord>,
        bodies: Map<String, ByteArray> = this.bodies,
    ): IndexBuild.Built = build(records, bodies) as? IndexBuild.Built ?: error("refused: ${build(records, bodies)}")

    /**
     * A generation as the sync would assemble it from [records]: [buildIndex]'s index, each full stored as a blob in
     * [store] and named in `meta.json`, each delta a file of the directory.
     */
    fun pending(
        store: StoreLayout,
        records: List<FilterRecord> = listOf(fullRecord, deltaRecord),
        bodies: Map<String, ByteArray> = this.bodies,
        trustClass: TrustClass = TrustClass.SIGNED,
        generationId: String = "1792587631204/${records.last().id}",
        sourceTimestampMillis: Long = 1_792_587_631_204,
        format: FilterFormat = FilterFormat.V3,
    ): PendingGeneration {
        val built = built(records, bodies)
        val blobs = LinkedHashMap<String, ByteString>()
        val deltas = LinkedHashMap<String, ByteArray>()
        for (p in built.filters) {
            val bytes = bodies.getValue(p.record.filename)
            if (p.full) {
                store.putBlob(bytes)
                blobs[p.name] = bytes.toByteString().sha256()
            } else {
                deltas[p.name] = bytes
            }
        }
        val signed = trustClass == TrustClass.SIGNED
        val meta =
            GenerationMeta(
                dataset = Dataset.CRLITE,
                channel = store.channel,
                trustClass = trustClass,
                generationId = generationId,
                format = format,
                freshness =
                    if (trustClass ==
                        TrustClass.BUNDLED
                    ) {
                        Freshness.SEED_SIGNED_TIME
                    } else {
                        Freshness.RECORD_LAST_MODIFIED
                    },
                sourceTimestampMillis = sourceTimestampMillis,
                collection = "security-state/cert-revocations",
                blobs = blobs,
                signed =
                    if (signed) {
                        SignedMeta(
                            sourceTimestampMillis,
                            ByteArray(32) {
                                7
                            }.toByteString(),
                            ByteArray(96) { 9 }.toByteString(),
                        )
                    } else {
                        null
                    },
            )
        return PendingGeneration(meta, built.index, deltas, if (signed) "{\"data\":[]}".encodeToByteArray() else null)
    }

    /** A logger that keeps every message. */
    class Recording : RevoktLogger {
        val messages = mutableListOf<Pair<LogLevel, String>>()

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            messages += level to message
        }
    }

    /**
     * The Kotlin engine with hooks each test sets: [onPrepare] and [onActivate] run first (and may throw),
     * [preparedAnswer] replaces the prepared state's answers (a constant-answer engine), [formats] what it lists. Every
     * prepared generation it closes is logged in [closed].
     */
    class TestEngine(
        override val formats: Set<FilterFormat> = setOf(FilterFormat.V3, FilterFormat.V4),
        val inner: KotlinRevocationEngine = KotlinRevocationEngine(),
    ) : RevocationEngine by inner {
        var onPrepare: (GenerationFiles) -> Unit = {}
        var onActivate: () -> Unit = {}
        var preparedAnswer: ((CrliteQuery) -> CrliteQueryResult)? = null
        var coverageEnd: () -> Long? = { inner.coverageEndMillis }
        val prepared = mutableListOf<String>()
        val closed = mutableListOf<String>()

        override val coverageEndMillis: Long? get() = coverageEnd()

        override fun prepare(generation: GenerationFiles): PreparedGeneration {
            prepared += generation.generationId
            onPrepare(generation)
            val real = inner.prepare(generation)
            val answer = preparedAnswer
            return Prepared(real, answer, closed)
        }

        override fun activate(prepared: PreparedGeneration) {
            onActivate()
            inner.activate((prepared as Prepared).real)
        }

        /** The generation the Kotlin engine holds live, from its toString. */
        val live: String? get() =
            inner.toString().removePrefix("KotlinRevocationEngine(live=").removeSuffix(")").takeIf {
                it !=
                    "null"
            }

        private class Prepared(
            val real: PreparedGeneration,
            val answer: ((CrliteQuery) -> CrliteQueryResult)?,
            val closed: MutableList<String>,
        ) : PreparedGeneration {
            override val generationId: String get() = real.generationId

            override fun query(q: CrliteQuery): CrliteQueryResult = answer?.invoke(q) ?: real.query(q)

            override fun close() {
                closed += generationId
                real.close()
            }
        }
    }

    // A v4 filter written field by field (spec §6.3), for coverage and blocks the corpus does not hold.

    class Block(
        val issuer: ByteString,
        val approxM: Int = 0,
        val rank: Int = 0,
        val exactM: Int = 0,
        val inverted: Boolean = false,
        val exceptions: List<ByteString> = emptyList(),
    )

    fun log(i: Int): ByteString =
        ByteArray(32) { (i ushr (8 * (it % 4))).toByte() }.also { it[31] = 0x5A }.toByteString()

    fun issuer(i: Int): ByteString = ByteArray(32) { i.toByte() }.toByteString()

    /**
     * A v4 clubcard with [coverage] (log to inclusive window) and [blocks], no approximate columns and one empty exact
     * column, so a block with `approxM > 0` holds every serial but its exceptions.
     */
    fun v4(
        coverage: List<Pair<ByteString, Pair<Long, Long>>>,
        blocks: List<Block> = emptyList(),
    ): ByteArray {
        val b = Buffer().writeByte(4).writeByte(0)
        b.writeShort(coverage.size)
        for ((logId, window) in coverage) b.write(logId).writeLong(window.first).writeLong(window.second)
        b.writeInt(blocks.size)
        for (k in blocks.sortedBy { it.issuer }) {
            b.write(k.issuer)
            b.writeInt(k.approxM).writeByte(k.rank).writeInt(0)
            b.writeInt(k.exactM).writeInt(0).writeByte(if (k.inverted) 1 else 0)
            b.writeShort(k.exceptions.size)
            for (x in k.exceptions) b.writeByte(x.size).write(x)
        }
        b.writeByte(0)
        b.writeInt(0)
        return b.readByteArray()
    }
}
