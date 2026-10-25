// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.producer.ProducerCorpus

/**
 * Oracle 3b of spec §9.2 (the independent TLV locator, `native/revokt-oracle locate`), read from its recorded goldens
 * (`oracle/3b.tsv`, keyed by the SHA-256 of the input). This step builds `canon(encoded)` from 3b's re-encoded TBS, TBS
 * signature AlgorithmIdentifier and signature octets. Regenerate with `native/revokt-oracle/record-goldens.sh`.
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

    private val goldens: Map<String, String> by lazy {
        String(ProducerCorpus.resource("oracle/3b.tsv"))
            .lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { line -> line.substringBefore('\t') to line.substringAfter('\t') }
    }

    /** sha256 of the input → 3b's reply, or null when no golden is recorded. */
    fun reply(sha256: String): String? = goldens[sha256]

    /** The reply parsed, or null for `NOT_LOCATED` and `PANIC`. */
    fun parts(reply: String): Parts? {
        val f = reply.split('\t')
        return if (f[0] == "CANON") Parts(f[1], f[2], f[3]) else null
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
