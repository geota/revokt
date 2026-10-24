// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/**
 * K7 (spec §9.2): the SPKI is an `AlgorithmIdentifier` and a BIT STRING with zero unused bits, holding one of
 * `rsaEncryption` with NULL parameters and `RSAPublicKey { n > 0, 0 < e < 2^31 }`, both minimal with nothing after;
 * `id-ecPublicKey` on P-256, P-384 or P-521 with an uncompressed point on the curve; Ed25519 with absent parameters and
 * 32 octets. Any other algorithm is outside the profile, so ct-go adding a parser later cannot break D8.
 */
internal object KeyabilityKey {
    private const val SEQUENCE = 0x30
    private const val INTEGER = 0x02
    private const val NULL = 0x05
    private const val OBJECT_IDENTIFIER = 0x06
    private const val UNCOMPRESSED = 0x04
    private const val ED25519_KEY_BYTES = 32
    private const val MAX_EXPONENT_BYTES = 4

    private val RSA = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01)
    private val EC = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01)
    private val ED25519 = byteArrayOf(0x2b, 0x65, 0x70)

    fun keyable(
        b: ByteArray,
        spki: Span,
    ): Boolean {
        val (algorithm, bits) = Keyability.spki(b, spki, exact = true) ?: return false
        if (bits.length < 1 || b[bits.start].toInt() != 0) return false
        val key = Span(bits.start + 1, bits.end)
        val (oid, parameters) = algorithm
        return when {
            Oid.matches(b, oid, RSA) -> {
                parameters != null && parameters.tag == NULL && parameters.content.length == 0 &&
                    rsa(b, key)
            }

            Oid.matches(b, oid, EC) -> {
                parameters != null && parameters.tag == OBJECT_IDENTIFIER &&
                    ec(b, parameters.content, key)
            }

            Oid.matches(b, oid, ED25519) -> {
                parameters == null && key.length == ED25519_KEY_BYTES
            }

            else -> {
                false
            }
        }
    }

    /** `RSAPublicKey { n INTEGER, e INTEGER }` filling the key, with minimal headers, n > 0 and 0 < e < 2^31. */
    private fun rsa(
        b: ByteArray,
        key: Span,
    ): Boolean =
        try {
            val ctx = ParseContext()
            val r = DerReader(b, key.start, key.end, ctx)
            val fields = r.child(r.read(SEQUENCE, HeaderSite.SPKI))
            r.requireEnd("RSAPublicKey")
            val n = fields.read(INTEGER, HeaderSite.SPKI).content
            val e = fields.read(INTEGER, HeaderSite.SPKI).content
            fields.requireEnd("RSAPublicKey")
            ctx.nonMinimal.isEmpty() && positive(b, n) && positive(b, e) && e.length <= MAX_EXPONENT_BYTES
        } catch (_: DerException) {
            false
        }

    /** A minimal INTEGER content that is above zero. */
    private fun positive(
        b: ByteArray,
        content: Span,
    ): Boolean =
        Keyability.minimalInteger(b, content) && b[content.start] >= 0 &&
            (content.length > 1 || b[content.start].toInt() != 0)

    private fun ec(
        b: ByteArray,
        curveOid: Span,
        key: Span,
    ): Boolean {
        val curve = PrimeCurve.ALL.firstOrNull { Oid.matches(b, curveOid, it.oid) } ?: return false
        val n = curve.byteLength
        if (key.length != 1 + 2 * n || b[key.start].toInt() != UNCOMPRESSED) return false
        val x = b.copyOfRange(key.start + 1, key.start + 1 + n)
        val y = b.copyOfRange(key.start + 1 + n, key.end)
        return curve.onCurve(x, y)
    }
}

/**
 * A NIST prime curve `y² = x³ − 3x + b (mod p)` with the modular arithmetic its on-curve check needs: little-endian
 * 32-bit limbs, multiplication by double-and-add. Common Kotlin only; speed is irrelevant at one point per leaf.
 */
internal class PrimeCurve(
    val oid: ByteArray,
    val byteLength: Int,
    pHex: String,
    bHex: String,
) {
    private val limbs = (byteLength + 3) / 4
    private val p = limbsOf(hex(pHex))
    private val b = limbsOf(hex(bHex))

    /** True when x and y, big-endian of the curve's length, are both below p and satisfy the curve equation. */
    fun onCurve(
        xBytes: ByteArray,
        yBytes: ByteArray,
    ): Boolean {
        val x = limbsOf(xBytes)
        val y = limbsOf(yBytes)
        if (compare(x, p) >= 0 || compare(y, p) >= 0) return false
        val threeX = add(add(x, x), x)
        val rhs = add(sub(mul(mul(x, x), x), threeX), b)
        return compare(mul(y, y), rhs) == 0
    }

    private fun limbsOf(bytes: ByteArray): IntArray {
        val out = IntArray(limbs)
        for (i in bytes.indices) {
            val bit = (bytes.size - 1 - i) * 8
            out[bit / 32] = out[bit / 32] or ((bytes[i].toInt() and 0xff) shl (bit % 32))
        }
        return out
    }

    private fun compare(
        a: IntArray,
        c: IntArray,
    ): Int {
        for (i in limbs - 1 downTo 0) {
            val cmp = (a[i].toLong() and MASK).compareTo(c[i].toLong() and MASK)
            if (cmp != 0) return cmp
        }
        return 0
    }

    /** (a + c) mod p for a, c below p. */
    private fun add(
        a: IntArray,
        c: IntArray,
    ): IntArray {
        val out = IntArray(limbs)
        var carry = 0L
        for (i in 0 until limbs) {
            val s = (a[i].toLong() and MASK) + (c[i].toLong() and MASK) + carry
            out[i] = s.toInt()
            carry = s ushr 32
        }
        return if (carry != 0L || compare(out, p) >= 0) rawSub(out, p) else out
    }

    /** (a − c) mod p for a, c below p. */
    private fun sub(
        a: IntArray,
        c: IntArray,
    ): IntArray = if (compare(a, c) >= 0) rawSub(a, c) else add(a, rawSub(p, c))

    /** a − c modulo 2^(32·limbs). */
    private fun rawSub(
        a: IntArray,
        c: IntArray,
    ): IntArray {
        val out = IntArray(limbs)
        var borrow = 0L
        for (i in 0 until limbs) {
            val d = (a[i].toLong() and MASK) - (c[i].toLong() and MASK) - borrow
            out[i] = d.toInt()
            borrow = if (d < 0) 1 else 0
        }
        return out
    }

    /** (a · c) mod p for a, c below p, by double-and-add over c's bits from the top. */
    private fun mul(
        a: IntArray,
        c: IntArray,
    ): IntArray {
        var r = IntArray(limbs)
        for (bit in limbs * 32 - 1 downTo 0) {
            r = add(r, r)
            if ((c[bit / 32] ushr (bit % 32)) and 1 != 0) r = add(r, a)
        }
        return r
    }

    companion object {
        private const val MASK = 0xffffffffL

        private fun hex(s: String): ByteArray =
            ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

        val P256 =
            PrimeCurve(
                byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07),
                32,
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            )
        val P384 =
            PrimeCurve(
                byteArrayOf(0x2b, 0x81.toByte(), 0x04, 0x00, 0x22),
                48,
                "ff".repeat(28) + "fffffffeffffffff0000000000000000ffffffff",
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a" +
                    "c656398d8a2ed19d2a85c8edd3ec2aef",
            )
        val P521 =
            PrimeCurve(
                byteArrayOf(0x2b, 0x81.toByte(), 0x04, 0x00, 0x23),
                66,
                "01ff" + "ff".repeat(64),
                "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1" +
                    "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            )
        val ALL = listOf(P256, P384, P521)
    }
}
