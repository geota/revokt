// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/** A test-only DER writer: minimal lengths unless a test asks for a specific header. */
internal object TestDer {
    fun length(n: Int): ByteArray =
        when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        }

    fun tlv(
        tag: Int,
        vararg content: ByteArray,
    ): ByteArray {
        val body = concat(*content)
        return byteArrayOf(tag.toByte()) + length(body.size) + body
    }

    /** A TLV whose length is written with the given raw header bytes (for non-minimal and malformed lengths). */
    fun tlvWithLength(
        tag: Int,
        lengthBytes: ByteArray,
        content: ByteArray,
    ): ByteArray = byteArrayOf(tag.toByte()) + lengthBytes + content

    fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, *parts)

    fun concat(vararg parts: ByteArray): ByteArray = parts.fold(ByteArray(0)) { acc, p -> acc + p }

    fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }

    fun ascii(text: String): ByteArray = text.encodeToByteArray()

    /** OID content for a dotted string (test inputs only, arcs below 2^63). */
    fun oidContent(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        val out = ArrayList<Byte>()

        fun arc(v: Long) {
            val groups = ArrayList<Int>()
            var x = v
            do {
                groups.add((x and 0x7f).toInt())
                x = x ushr 7
            } while (x != 0L)
            for (i in groups.indices.reversed()) out.add((groups[i] or if (i != 0) 0x80 else 0).toByte())
        }
        arc(arcs[0] * 40 + arcs[1])
        arcs.drop(2).forEach { arc(it) }
        return out.toByteArray()
    }

    fun oid(dotted: String): ByteArray = tlv(0x06, oidContent(dotted))

    fun extension(
        oid: String,
        value: ByteArray,
        critical: Boolean? = null,
    ): ByteArray =
        seq(
            oid(oid),
            if (critical == null) ByteArray(0) else tlv(0x01, bytes(if (critical) 0xff else 0)),
            tlv(0x04, value),
        )
}

/**
 * A certificate assembled from replaceable parts; every part is the exact bytes the parser must report. Defaults are
 * a structurally valid v3 certificate (the signature is not a real signature: the parser never checks it).
 */
internal class TestCert(
    val version: ByteArray = TestDer.tlv(0xa0, TestDer.tlv(0x02, TestDer.bytes(2))),
    val serial: ByteArray = TestDer.tlv(0x02, TestDer.bytes(0x00, 0x8f, 0x12, 0x34)),
    val tbsSignature: ByteArray = TestDer.seq(TestDer.oid("1.2.840.10045.4.3.2")),
    val issuer: ByteArray = name("Test CA"),
    val validity: ByteArray =
        TestDer.seq(
            TestDer.tlv(0x17, TestDer.ascii("261022134530Z")),
            TestDer.tlv(0x18, TestDer.ascii("20500101000000Z")),
        ),
    val subject: ByteArray = name("leaf.example"),
    val spki: ByteArray =
        TestDer.seq(
            TestDer.seq(TestDer.oid("1.2.840.10045.2.1"), TestDer.oid("1.2.840.10045.3.1.7")),
            TestDer.tlv(0x03, TestDer.bytes(0x00, 0x04, 0x01, 0x02, 0x03)),
        ),
    val uniqueIds: ByteArray = ByteArray(0),
    val extensions: List<ByteArray> =
        listOf(
            TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, TestDer.tlv(0x04, TestDer.bytes(1, 2, 3, 4))),
            TestDer.extension("2.5.29.19", TestDer.seq(), critical = true),
        ),
    val extensionsWrapper: (List<ByteArray>) -> ByteArray = { exts ->
        if (exts.isEmpty()) ByteArray(0) else TestDer.tlv(0xa3, TestDer.seq(*exts.toTypedArray()))
    },
    val tbsTrailing: ByteArray = ByteArray(0),
    val outerAlgorithm: ByteArray = TestDer.seq(TestDer.oid("1.2.840.10045.4.3.2")),
    val signature: ByteArray = TestDer.tlv(0x03, TestDer.bytes(0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)),
    val certificateTrailing: ByteArray = ByteArray(0),
    val outerTrailing: ByteArray = ByteArray(0),
) {
    val tbs: ByteArray =
        TestDer.seq(
            version,
            serial,
            tbsSignature,
            issuer,
            validity,
            subject,
            spki,
            uniqueIds,
            extensionsWrapper(extensions),
            tbsTrailing,
        )

    val der: ByteArray = TestDer.seq(tbs, outerAlgorithm, signature, certificateTrailing) + outerTrailing

    companion object {
        fun name(cn: String): ByteArray =
            TestDer.seq(TestDer.tlv(0x31, TestDer.seq(TestDer.oid("2.5.4.3"), TestDer.tlv(0x0c, TestDer.ascii(cn)))))
    }
}
