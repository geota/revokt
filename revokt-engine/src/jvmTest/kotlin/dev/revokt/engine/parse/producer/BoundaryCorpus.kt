// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.extension
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.TestDer.tlvWithLength

/**
 * The boundary corpus of spec §9.2 D8 (revision 35), K1–K7 edges: synthetic leaves at each clause's edge, accept side
 * unless named `reject-`. Every input is deterministic; the oracle-4 verdicts are recorded in `producer/goldens.tsv`.
 * The real-certificate entries (the unsigned-header forms) are in [ProducerCorpus].
 */
internal object BoundaryCorpus {
    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private val ecPublicKey = oid("1.2.840.10045.2.1")

    private fun ec(
        curve: String,
        x: String,
        y: String,
    ) = seq(seq(ecPublicKey, oid(curve)), tlv(0x03, bytes(0, 0x04), hex(x), hex(y)))

    private const val P256 = "1.2.840.10045.3.1.7"
    private const val P384 = "1.3.132.0.34"
    private const val P521 = "1.3.132.0.35"

    /** The NIST generators, and JDK-generated points recorded once (JDK 21, 2026-10-24). */
    private val points =
        listOf(
            Triple(
                P256,
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            ),
            Triple(
                P384,
                "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            ),
            Triple(
                P521,
                "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
                "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            ),
            Triple(
                P256,
                "de277911106cd6b500d9ab3c97df1500661658ed9591cf70255116a3de18e33b",
                "b0d8a49a95f84493e18fe71d2a8820a4252a5c81946bfa1d384d063b5f2feb2c",
            ),
            Triple(
                P384,
                "8625dbba9a769aad07e19a5bac0e7fd9d908ae69056613bf7311ad776e9d73ec8f27c538e79cdd4bee6ae0318d246a6c",
                "a8c44a3f44d0d95ff7b8cca493ea2294b1ffc1d14651002aa7c042c52348f820ec1b1c27c395b6c1e0edb7ebea398c6e",
            ),
            Triple(
                P521,
                "00f543d819a08710e26cc18b3c536c61bb36450ad305be465cb37ad57547914afe935f5a9ba211bda69d605a6aa4c351c9b6d5b5c0c504737983bf17c40004a99e2f",
                "004b8b95bed49d9b3e0fe8ac250f8a22367485becc9530576ce60adfc99a7ad10989e85b12287c7790acc5d4a2a38dd61c871ca6701f45ba3c9bf7c3ea8bccaca034",
            ),
            // x = p − 1 on P-384 (none exists on P-256).
            Triple(
                P384,
                "ff".repeat(28) + "fffffffeffffffff0000000000000000fffffffe",
                "8cdeadbbd04911a3c1931e26df3fa6439dca9c7eb286fbd46fc319f0e2bb780232baf57825fc0c1912ada2fefe84024c",
            ),
        )

    private val unknown = extension("1.3.6.1.4.1.99999.1", tlv(0x04, bytes(1, 2)))

    /** A leaf inside the profile: v3, P-256, one opaque extension, nothing K8 lists. */
    fun base(
        serial: ByteArray = tlv(0x02, bytes(0x00, 0x8f, 0x12, 0x34)),
        subject: ByteArray = TestCert.name("leaf.example"),
        validity: ByteArray = seq(tlv(0x17, ascii("261022134530Z")), tlv(0x18, ascii("20500101000000Z"))),
        spki: ByteArray = ec(points[0].first, points[0].second, points[0].third),
        extensions: List<ByteArray> = listOf(unknown),
        signature: ByteArray = tlv(0x03, bytes(0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)),
    ): ByteArray =
        TestCert(
            serial = serial,
            subject = subject,
            validity = validity,
            spki = spki,
            extensions = extensions,
            signature = signature,
        ).der

    private fun times(
        notBefore: ByteArray,
        notAfter: ByteArray,
    ) = base(validity = seq(notBefore, notAfter))

    private fun utc(s: String) = tlv(0x17, ascii(s))

    private fun gen(s: String) = tlv(0x18, ascii(s))

    private fun rsa(
        n: ByteArray,
        e: ByteArray,
        nonMinimalKeyHeader: Boolean = false,
    ): ByteArray {
        val body = tlv(0x02, n) + tlv(0x02, e)
        // One superfluous leading zero octet on the RSAPublicKey SEQUENCE's length (ct-go rejects it, K7).
        val lengthOctets =
            byteArrayOf(0) +
                body.size
                    .toBigInteger()
                    .toByteArray()
                    .dropWhile { it.toInt() == 0 }
        val key =
            if (nonMinimalKeyHeader) {
                tlvWithLength(
                    0x30,
                    byteArrayOf((0x80 or lengthOctets.size).toByte()) + lengthOctets,
                    body,
                )
            } else {
                seq(body)
            }
        return seq(seq(oid("1.2.840.113549.1.1.1"), tlv(0x05)), tlv(0x03, bytes(0), key))
    }

    fun inputs(rsaModulus: ByteArray): List<Pair<String, ByteArray>> {
        val out = ArrayList<Pair<String, ByteArray>>()
        out += "base" to base()
        out += "oid-arc-2^31-1" to base(extensions = listOf(extension("1.3.6.1.4.1.2147483647", ByteArray(0))))
        out += "oid-first-subidentifier-limit" to base(extensions = listOf(extension("2.2147483567", ByteArray(0))))
        out += "leap-day-2000" to times(gen("20000229000000Z"), gen("20500101000000Z"))
        out += "leap-day-2024" to times(gen("20240229000000Z"), gen("20500101000000Z"))
        out += "leap-day-utc-52" to times(utc("520229000000Z"), gen("20500101000000Z"))
        out += "year-1950" to times(utc("500101000000Z"), utc("491231235959Z"))
        out += "year-2049-2050" to times(utc("491231235959Z"), gen("20500101000000Z"))
        out += "year-9999" to times(utc("261022134530Z"), gen("99991231235959Z"))
        out += "rsa-e-2^31-1" to base(spki = rsa(rsaModulus, bytes(0x7f, 0xff, 0xff, 0xff)))
        out += "rsa-e-65537" to base(spki = rsa(rsaModulus, bytes(0x01, 0x00, 0x01)))
        out +=
            "explicit-false" to
            base(extensions = listOf(extension("1.3.6.1.4.1.99999.2", ByteArray(0), critical = false)))
        out += "negative-serial" to base(serial = tlv(0x02, bytes(0xff, 0x01)))
        out += "21-octet-serial" to base(serial = tlv(0x02, ByteArray(21) { (it + 1).toByte() }))
        out += "printable-star-ampersand" to
            base(subject = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x13, ascii("*.a&b.example"))))))
        out +=
            "ed25519" to base(spki = seq(seq(oid("1.3.101.112")), tlv(0x03, bytes(0), ByteArray(32) { it.toByte() })))
        // u = 00 read as a tag, then length 02 and two octets: JDK 11 reads this indefinite signatureValue (revision 35).
        out += "indefinite-signature-value" to base(signature = bytes(0x03, 0x80, 0x00, 0x02, 0x01, 0x05, 0x00, 0x00))
        for ((i, p) in points.withIndex()) {
            val (curve, x, y) = p
            out += "ec-point-$i" to base(spki = ec(curve, x, y))
            val flipped = hex(y).also { it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte() }
            out += "reject-ec-point-$i-flipped" to
                base(spki = seq(seq(ecPublicKey, oid(curve)), tlv(0x03, bytes(0, 0x04), hex(x), flipped)))
        }
        out +=
            "reject-rsa-key-header-non-minimal" to
            base(spki = rsa(rsaModulus, bytes(0x01, 0x00, 0x01), nonMinimalKeyHeader = true))
        return out
    }
}
