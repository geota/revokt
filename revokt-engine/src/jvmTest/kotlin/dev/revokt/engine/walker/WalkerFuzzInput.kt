// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.testing.AlgMismatch
import dev.revokt.testing.ChainGenerator
import dev.revokt.testing.CrossCertToNonAnchor
import dev.revokt.testing.DepthPad
import dev.revokt.testing.DropIntermediate
import dev.revokt.testing.Duplicate
import dev.revokt.testing.EndEntityIssuer
import dev.revokt.testing.Loop
import dev.revokt.testing.Mutation
import dev.revokt.testing.NameEncoding
import dev.revokt.testing.Permute
import dev.revokt.testing.Recover
import dev.revokt.testing.SameKeyDecoy
import dev.revokt.testing.SelfSignedNonAnchor
import dev.revokt.testing.Stuff
import dev.revokt.testing.UnsupportedOwnSig
import java.io.ByteArrayOutputStream

/**
 * The walker fuzzer's structured input (spec §9.1: "the mutation list as the structured input"), decoded from the
 * bytes libFuzzer mutates. Every byte string decodes: a field past the end reads as zero, and bytes past [MAX_BYTES]
 * are ignored. The layout, big-endian:
 *
 * | bytes | field |
 * |---|---|
 * | 1 | flags: bit 0 [revoked], bits 1–3 the [ThrowKind] ordinal (`NONE` above the last) |
 * | 8 | [seed] |
 * | 1 | [depth], modulo `MAX_GENERATED_DEPTH + 1` |
 * | 1 | [anchors], 1 + the byte modulo `MAX_ANCHORS` |
 * | 4 | [throwSelector] |
 * | 8 | [permuteSeed] |
 * | … | up to [MAX_MUTATIONS] mutations, each a kind byte (modulo the 14 kinds, in [kinds] order) and its fields |
 *
 * A mutation's fields are read in declaration order: an `Int` as 4 bytes, a `Long` as 8, a `Boolean` as 1 (bit 0),
 * `Stuff.n` as 2 bytes modulo `Stuff.MAX + 1`, `DepthPad.length` as 1 byte (1 + modulo `DepthPad.MAX`), and
 * `Recover.certifiedBy` as a presence byte (bit 0) then 4 bytes. A mutation starts only where a byte remains.
 */
internal class WalkerFuzzInput(
    val revoked: Boolean,
    val throwKind: ThrowKind,
    val seed: Long,
    val depth: Int,
    val anchors: Int,
    val throwSelector: Int,
    val permuteSeed: Long,
    val mutations: List<Mutation>,
) {
    /** What the fuzzer's verifier throws on the selected key's links ([ThrowKind.NONE]: it never throws). */
    enum class ThrowKind { NONE, RUNTIME, IO, ASSERTION, STACK_OVERFLOW, INTERRUPTED }

    override fun toString(): String =
        "WalkerFuzzInput(seed=$seed, depth=$depth, anchors=$anchors, revoked=$revoked, throw=$throwKind" +
            "@$throwSelector, permute=$permuteSeed, mutations=$mutations)"

    /** This input's bytes: [decode] of them is equal to it. */
    @Suppress("CyclomaticComplexMethod") // one branch per mutation kind, as in decode
    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((if (revoked) 1 else 0) or (throwKind.ordinal shl 1))
        long(out, seed)
        out.write(depth)
        out.write(anchors - 1)
        int(out, throwSelector)
        long(out, permuteSeed)
        for (m in mutations) {
            out.write(KINDS.indexOf(m::class.simpleName))
            when (m) {
                is NameEncoding -> {
                    int(out, m.target)
                }

                is AlgMismatch -> {
                    int(out, m.target)
                }

                is UnsupportedOwnSig -> {
                    int(out, m.target)
                }

                is DropIntermediate -> {
                    int(out, m.target)
                }

                is Recover -> {
                    int(out, m.child)
                    out.write(if (m.certifiedBy == null) 0 else 1)
                    int(out, m.certifiedBy ?: 0)
                }

                is EndEntityIssuer -> {
                    int(out, m.child)
                    int(out, m.certifiedBy)
                    out.write(if (m.unrelated) 1 else 0)
                }

                is SameKeyDecoy -> {
                    int(out, m.target)
                }

                is CrossCertToNonAnchor -> {
                    int(out, m.target)
                }

                is Stuff -> {
                    out.write(m.n ushr 8)
                    out.write(m.n and 0xff)
                    out.write(if (m.related) 1 else 0)
                    int(out, m.at)
                }

                is SelfSignedNonAnchor -> {
                    int(out, m.child)
                }

                is Loop -> {
                    int(out, m.child)
                }

                is Permute -> {
                    long(out, m.seed)
                }

                is Duplicate -> {
                    int(out, m.source)
                    int(out, m.position)
                }

                is DepthPad -> {
                    int(out, m.at)
                    out.write(m.length - 1)
                }
            }
        }
        val bytes = out.toByteArray()
        check(bytes.size <= MAX_BYTES) { "an input of ${bytes.size} bytes, over $MAX_BYTES" }
        return bytes
    }

    companion object {
        /** The bytes read; `-max_len` is one more (CONTRIBUTING §6). */
        const val MAX_BYTES: Int = 128
        const val MAX_MUTATIONS: Int = 8

        /** The kind byte's names, in `Mutation`'s order. */
        private val KINDS =
            listOf(
                "NameEncoding",
                "AlgMismatch",
                "UnsupportedOwnSig",
                "DropIntermediate",
                "Recover",
                "EndEntityIssuer",
                "SameKeyDecoy",
                "CrossCertToNonAnchor",
                "Stuff",
                "SelfSignedNonAnchor",
                "Loop",
                "Permute",
                "Duplicate",
                "DepthPad",
            )

        fun decode(data: ByteArray): WalkerFuzzInput {
            val r = Reader(data, minOf(data.size, MAX_BYTES))
            val flags = r.byte()
            val throwKind = ThrowKind.entries.getOrElse((flags ushr 1) and 7) { ThrowKind.NONE }
            val seed = r.long()
            val depth = r.byte() % (ChainGenerator.MAX_GENERATED_DEPTH + 1)
            val anchors = 1 + r.byte() % ChainGenerator.MAX_ANCHORS
            val throwSelector = r.int()
            val permuteSeed = r.long()
            val mutations = ArrayList<Mutation>()
            while (r.hasMore() && mutations.size < MAX_MUTATIONS) mutations += mutation(r)
            return WalkerFuzzInput(
                flags and 1 == 1,
                throwKind,
                seed,
                depth,
                anchors,
                throwSelector,
                permuteSeed,
                mutations,
            )
        }

        @Suppress("CyclomaticComplexMethod") // one branch per mutation kind
        private fun mutation(r: Reader): Mutation =
            when (r.byte() % KINDS.size) {
                0 -> NameEncoding(r.int())
                1 -> AlgMismatch(r.int())
                2 -> UnsupportedOwnSig(r.int())
                3 -> DropIntermediate(r.int())
                4 -> Recover(r.int(), r.bool().let { present -> r.int().takeIf { present } })
                5 -> EndEntityIssuer(r.int(), r.int(), r.bool())
                6 -> SameKeyDecoy(r.int())
                7 -> CrossCertToNonAnchor(r.int())
                8 -> Stuff(((r.byte() shl 8) or r.byte()) % (Stuff.MAX + 1), r.bool(), r.int())
                9 -> SelfSignedNonAnchor(r.int())
                10 -> Loop(r.int())
                11 -> Permute(r.long())
                12 -> Duplicate(r.int(), r.int())
                else -> DepthPad(r.int(), 1 + r.byte() % DepthPad.MAX)
            }

        private fun int(
            out: ByteArrayOutputStream,
            v: Int,
        ) {
            for (shift in 24 downTo 0 step 8) out.write(v ushr shift)
        }

        private fun long(
            out: ByteArrayOutputStream,
            v: Long,
        ) {
            for (shift in 56 downTo 0 step 8) out.write((v ushr shift).toInt())
        }
    }

    /** Reads [data] up to [end]; past it every byte reads as zero. */
    private class Reader(
        private val data: ByteArray,
        private val end: Int,
    ) {
        private var at = 0

        fun hasMore(): Boolean = at < end

        fun byte(): Int = if (at < end) data[at++].toInt() and 0xff else 0.also { at++ }

        fun bool(): Boolean = byte() and 1 == 1

        fun int(): Int = (0 until 4).fold(0) { acc, _ -> (acc shl 8) or byte() }

        fun long(): Long = (0 until 8).fold(0L) { acc, _ -> (acc shl 8) or byte().toLong() }
    }
}
