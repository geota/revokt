// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import java.io.ByteArrayOutputStream

/** How a test writes one header's length. */
internal sealed class LengthForm {
    object Minimal : LengthForm()

    object Indefinite : LengthForm()

    /** Long form with exactly [octets] length octets, leading zeros as needed. */
    class Long(
        val octets: Int,
    ) : LengthForm()
}

/**
 * A test-only DER tree for building envelope variants of real certificates: constructed elements are split into
 * children, primitives keep their content. [form] says how the header is written back; an indefinite primitive is
 * written as `tag 80 content 00 00`, which the JDK's converter reads only when the content is itself TLVs.
 */
internal class DerNode(
    val tag: Int,
    var content: ByteArray,
    val children: MutableList<DerNode>?,
    var form: LengthForm = LengthForm.Minimal,
) {
    fun child(vararg path: Int): DerNode = path.fold(this) { node, i -> node.children!![i] }

    fun copy(): DerNode = DerNode(tag, content.copyOf(), children?.map { it.copy() }?.toMutableList(), form)

    fun encode(): ByteArray {
        val body = children?.let { kids -> kids.fold(ByteArray(0)) { acc, k -> acc + k.encode() } } ?: content
        val out = ByteArrayOutputStream()
        out.write(tag)
        when (val f = form) {
            LengthForm.Minimal -> {
                out.write(TestDer.length(body.size))
            }

            LengthForm.Indefinite -> {
                out.write(0x80)
            }

            is LengthForm.Long -> {
                out.write(0x80 or f.octets)
                for (i in f.octets - 1 downTo 0) out.write(if (i >= 4) 0 else (body.size ushr (8 * i)) and 0xff)
            }
        }
        out.write(body)
        if (form == LengthForm.Indefinite) out.write(byteArrayOf(0, 0))
        return out.toByteArray()
    }

    companion object {
        /** Parses minimal-DER [der]; primitives are not descended into. */
        fun parse(der: ByteArray): DerNode = parseAt(der, 0).first

        private fun parseAt(
            der: ByteArray,
            start: Int,
        ): Pair<DerNode, Int> {
            val tag = der[start].toInt() and 0xff
            var p = start + 1
            val first = der[p++].toInt() and 0xff
            var length = first
            if (first >= 0x80) {
                length = 0
                repeat(first and 0x7f) { length = (length shl 8) or (der[p++].toInt() and 0xff) }
            }
            val end = p + length
            val content = der.copyOfRange(p, end)
            if (tag and 0x20 == 0) return DerNode(tag, content, null) to end
            val children = ArrayList<DerNode>()
            var q = p
            while (q < end) {
                val (child, next) = parseAt(der, q)
                children.add(child)
                q = next
            }
            return DerNode(tag, content, children) to end
        }
    }
}
