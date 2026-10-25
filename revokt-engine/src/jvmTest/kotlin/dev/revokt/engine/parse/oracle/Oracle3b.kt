// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.producer.ProducerCorpus

/**
 * Oracle 3b of spec §9.2 (the independent TLV locator, `native/revokt-oracle locate`), read from its recorded goldens
 * (`oracle/3b.tsv`, keyed by the SHA-256 of the input): `canon(encoded)` from 3b's re-encoded TBS, TBS signature
 * AlgorithmIdentifier and signature octets, and the fields its TBS walk slices. Regenerate with
 * `native/revokt-oracle/record-goldens.sh`.
 */
internal object Oracle3b {
    /** 3b's `CANON` reply; every field is lower-case hex. */
    class Parts(
        val tbs: String,
        val tbsSignature: String,
        val signature: String,
    ) {
        /** `canon(encoded)`: `SEQUENCE { tbs, tbsSignature, BIT STRING { 00, signature } }`, every new header minimal. */
        fun canon(): ByteArray {
            val bits = byteArrayOf(0) + Oracle3a.bytes(signature)
            val content = Oracle3a.bytes(tbs) + Oracle3a.bytes(tbsSignature) + tlv(0x03, bits)
            return tlv(0x30, content)
        }
    }

    /** 3b's `LOCATED` reply: the walk's fields; [stop] is the identifier octet that ended the TBS tail read. */
    class Located(
        val serial: String,
        val spki: String,
        val subject: String,
        val issuer: String,
        val parts: Parts,
        val unusedBits: Int?,
        val extensions: List<Oracle3a.Extension>,
        val stop: Int?,
    ) {
        /**
         * Whether the walk ignored an element with tag number 3 that is not a constructed context-specific `[3]`, which
         * 3a takes as extensions (`3A_TBS_LAX`, spec §9.2 revision 37).
         */
        val tagThreeIgnored: Boolean get() = stop != null && stop and 0x1f == 3 && stop != 0xa3
    }

    private val goldens: Map<String, String> by lazy {
        String(ProducerCorpus.resource("oracle/3b.tsv"))
            .lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { line -> line.substringBefore('\t') to line.substringAfter('\t') }
    }

    /** sha256 of the input → 3b's reply, or null when no golden is recorded. */
    fun reply(sha256: String): String? = goldens[sha256]

    /** The `canon` parts of a `LOCATED` or `CANON` reply, or null for `NOT_LOCATED` and `PANIC`. */
    fun parts(reply: String): Parts? {
        val f = reply.split('\t')
        return when (f[0]) {
            "LOCATED" -> Parts(f[5], f[6], f[7])
            "CANON" -> Parts(f[1], f[2], f[3])
            else -> null
        }
    }

    /** The walk's fields, or null unless the reply is `LOCATED`. */
    fun located(reply: String): Located? {
        val f = reply.split('\t')
        if (f[0] != "LOCATED") return null
        return Located(
            f[1],
            f[2],
            f[3],
            f[4],
            Parts(f[5], f[6], f[7]),
            f[8].toIntOrNull(),
            Oracle3a.extensions(f[9]),
            f[10].takeIf { it != "-" }?.toInt(16),
        )
    }

    private fun tlv(
        tag: Int,
        content: ByteArray,
    ): ByteArray {
        val n = content.size
        val length =
            when {
                n < 0x80 -> byteArrayOf(n.toByte())
                n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
                n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
                else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
            }
        return byteArrayOf(tag.toByte()) + length + content
    }
}
