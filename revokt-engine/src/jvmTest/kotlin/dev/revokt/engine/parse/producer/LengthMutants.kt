// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import java.io.ByteArrayOutputStream

/**
 * The spec §9.2 / #11 mutation set: one mutant per TLV header a best-effort recursive DER walk finds in a certificate.
 * The walk descends into constructed elements and into OCTET STRING and BIT STRING contents that are themselves exactly
 * a sequence of TLVs. Each mutant re-encodes that one header's length with one superfluous leading zero octet and
 * every ancestor minimally. Deterministic: the same certificate always yields the same mutants in the same order.
 */
internal object LengthMutants {
    class Mutant(
        val path: String,
        val der: ByteArray,
    )

    private class Node(
        val path: String,
        val offset: Int,
        val tag: Int,
        val contentStart: Int,
        val contentEnd: Int,
        val parent: Node?,
    )

    private class Header(
        val tag: Int,
        val contentStart: Int,
        val length: Int,
    )

    private fun header(
        b: ByteArray,
        i: Int,
        end: Int,
    ): Header? {
        if (i + 2 > end) return null
        val tag = b[i].toInt() and 0xff
        if (tag and 0x1f == 0x1f) return null
        val first = b[i + 1].toInt() and 0xff
        var p = i + 2
        val n: Int
        if (first < 0x80) {
            n = first
        } else {
            if (first == 0x80 || first == 0xff) return null
            val k = first and 0x7f
            if (k > 4 || p + k > end) return null
            var v = 0L
            repeat(k) { v = (v shl 8) or (b[p + it].toLong() and 0xff) }
            if (v > Int.MAX_VALUE) return null
            p += k
            n = v.toInt()
        }
        if (p + n > end) return null
        return Header(tag, p, n)
    }

    private fun children(
        b: ByteArray,
        s: Int,
        e: Int,
    ): List<Triple<Int, Header, Int>>? {
        val out = ArrayList<Triple<Int, Header, Int>>()
        var i = s
        while (i < e) {
            val h = header(b, i, e) ?: return null
            out.add(Triple(i, h, h.contentStart + h.length))
            i = h.contentStart + h.length
        }
        return out
    }

    private fun walk(
        b: ByteArray,
        s: Int,
        e: Int,
        path: String,
        parent: Node?,
        out: MutableList<Node>,
        depth: Int,
    ) {
        val kids = children(b, s, e) ?: return
        if (depth > 12) return
        for ((idx, kid) in kids.withIndex()) {
            val (offset, h, end) = kid
            val p = "$path/$idx:${h.tag.toString(16).padStart(2, '0')}"
            val node = Node(p, offset, h.tag, h.contentStart, end, parent)
            out.add(node)
            when {
                h.tag and 0x20 != 0 -> {
                    walk(b, h.contentStart, end, p, node, out, depth + 1)
                }

                h.tag == 0x04 && end > h.contentStart -> {
                    walk(b, h.contentStart, end, "$p~", node, out, depth + 1)
                }

                h.tag == 0x03 && end - h.contentStart > 1 && b[h.contentStart].toInt() == 0 -> {
                    walk(b, h.contentStart + 1, end, "$p~", node, out, depth + 1)
                }
            }
        }
    }

    private fun length(
        n: Int,
        extra: Boolean,
    ): ByteArray {
        if (!extra && n < 0x80) return byteArrayOf(n.toByte())
        val bytes = ArrayList<Byte>()
        var x = n
        do {
            bytes.add(0, (x and 0xff).toByte())
            x = x ushr 8
        } while (x != 0)
        if (extra) bytes.add(0, 0)
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    private fun rebuild(
        b: ByteArray,
        target: Int,
        descended: Set<Int>,
    ): ByteArray {
        fun build(
            s: Int,
            e: Int,
        ): ByteArray {
            val out = ByteArrayOutputStream()
            var i = s
            while (i < e) {
                val h = header(b, i, e)!!
                val end = h.contentStart + h.length
                val body =
                    when {
                        h.tag and 0x20 != 0 -> build(h.contentStart, end)
                        i in descended && h.tag == 0x03 -> byteArrayOf(0) + build(h.contentStart + 1, end)
                        i in descended -> build(h.contentStart, end)
                        else -> b.copyOfRange(h.contentStart, end)
                    }
                out.write(h.tag)
                out.write(length(body.size, extra = i == target))
                out.write(body)
                i = end
            }
            return out.toByteArray()
        }
        return build(0, b.size)
    }

    fun of(der: ByteArray): List<Mutant> {
        val nodes = ArrayList<Node>()
        walk(der, 0, der.size, "", null, nodes, 0)
        // An OCTET or BIT STRING is rebuilt from its parts only when the walk descended into it.
        val descended =
            nodes
                .filter {
                    it.path
                        .substringBeforeLast(
                            '/',
                        ).endsWith("~")
                }.mapNotNull { it.parent?.offset }
                .toSet()
        check(rebuild(der, -1, descended).contentEquals(der)) { "mutator does not reproduce the certificate" }
        return nodes.map { Mutant(it.path, rebuild(der, it.offset, descended)) }
    }
}
