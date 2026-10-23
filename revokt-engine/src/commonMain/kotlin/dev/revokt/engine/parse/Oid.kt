// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/** OID content decoding (lenient: non-minimal arcs are accepted, spec §9.2) and the OIDs the parser looks up. */
internal object Oid {
    /** Signed Certificate Timestamp list, RFC 6962 §3.3. */
    const val SCT_LIST: String = "1.3.6.1.4.1.11129.2.4.2"

    const val SUBJECT_KEY_IDENTIFIER: String = "2.5.29.14"
    const val AUTHORITY_KEY_IDENTIFIER: String = "2.5.29.35"

    /** Dotted form of OID content bytes, or null when the content is empty, ends mid-arc or has an arc over 2^63. */
    fun dotted(
        der: ByteArray,
        content: Span,
    ): String? {
        if (content.length == 0) return null
        val arcs = ArrayList<Long>()
        var value = 0L
        var inArc = false
        for (i in content.start until content.end) {
            val b = der[i].toInt() and 0xff
            if (value > (Long.MAX_VALUE shr 7)) return null
            value = (value shl 7) or (b and 0x7f).toLong()
            inArc = b and 0x80 != 0
            if (!inArc) {
                arcs.add(value)
                value = 0
            }
        }
        if (inArc) return null
        val first = arcs[0]
        val head =
            if (first < 40) {
                "0.$first"
            } else if (first < 80) {
                "1.${first - 40}"
            } else {
                "2.${first - 80}"
            }
        return (listOf(head) + arcs.drop(1).map { it.toString() }).joinToString(".")
    }
}
