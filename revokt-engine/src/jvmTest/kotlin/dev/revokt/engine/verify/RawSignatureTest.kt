// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.verify.JcaFixtures
import java.math.BigInteger
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §9 "Verifier: raw-to-DER edge cases" and §7.1 ("the `signature` field is base64url of raw r‖s, converted to DER
 * for `SHA384withECDSA`"), with Firefox's length rule (any non-empty even pair, maintainer decision on #163): the
 * decoder's alphabet and lengths, and the conversion's minimal INTEGERs, against the JDK's own P1363 and DER forms.
 */
class RawSignatureTest {
    private val url = Base64.getUrlEncoder().withoutPadding()

    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun half(
        first: Int,
        fill: Int = 0x11,
        size: Int = 48,
    ): ByteArray = ByteArray(size) { if (it == 0) first.toByte() else fill.toByte() }

    @Test
    fun `decode reads unpadded base64url of every even length from 2 to 132 bytes`() {
        for (size in 2..RawSignature.MAX_RAW_BYTES step 2) {
            val raw = ByteArray(size) { (it * 37 + size).toByte() }
            assertContentEquals(raw, RawSignature.decode(url.encodeToString(raw)), "$size bytes")
        }
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val every = (alphabet + alphabet).take(128)
        assertContentEquals(Base64.getUrlDecoder().decode(every), RawSignature.decode(every))
        assertContentEquals(ByteArray(96), RawSignature.decode("A".repeat(128)))
        assertContentEquals(ByteArray(96) { -1 }, RawSignature.decode("_".repeat(128)))
        // As in Firefox, a final partial group's unused low bits are not checked: "AAB" and "AAA" are both 00 00.
        assertContentEquals(ByteArray(2), RawSignature.decode("AAB"))
    }

    @Test
    fun `decode rejects an odd byte count, more than 132 bytes, padding and any other character`() {
        for (size in listOf(1, 3, 95, 97, 131, 133, 134, 200)) {
            assertNull(RawSignature.decode(url.encodeToString(ByteArray(size))), "$size bytes")
        }
        for (length in listOf(0, 1, 5, 125, 129, 177)) assertNull(RawSignature.decode("A".repeat(length)), "$length")
        assertNull(RawSignature.decode("AAA="), "padding")
        assertNull(RawSignature.decode("AA=="), "padding")
        val text = "A".repeat(128)
        val outside =
            (0..0x2FF).map { it.toChar() }.filter {
                it !in 'A'..'Z' && it !in 'a'..'z' && it !in '0'..'9' && it != '-' && it != '_'
            }
        for (c in outside + listOf('\u0660', '\uff10', '\ud83d')) {
            for (at in listOf(0, 1, 2, 3, 64, 127)) {
                assertNull(
                    RawSignature.decode(text.substring(0, at) + c + text.substring(at + 1)),
                    "U+%04X at $at".format(c.code),
                )
            }
        }
    }

    @Test
    fun `r and s become minimal non-negative INTEGERs`() {
        // High bit set: a 0x00 is prepended.
        assertContentEquals(
            byteArrayOf(0x30, 0x66, 0x02, 0x31, 0x00) + half(0x80) + byteArrayOf(0x02, 0x31, 0x00) + half(0xFF),
            RawSignature.toDer(half(0x80) + half(0xFF)),
        )
        // High bit clear: as is.
        assertContentEquals(
            byteArrayOf(0x30, 0x64, 0x02, 0x30) + half(0x7F) + byteArrayOf(0x02, 0x30) + half(0x01),
            RawSignature.toDer(half(0x7F) + half(0x01)),
        )
        // Leading zero bytes dropped, then a 0x00 back when the next byte's high bit is set.
        val r =
            ByteArray(48).also {
                it[3] = 0x12
                it[47] = 0x34
            }
        val s = ByteArray(48).also { it[1] = 0x80.toByte() }
        assertContentEquals(
            byteArrayOf(0x30, 0x61, 0x02, 0x2D) + r.copyOfRange(3, 48) + byteArrayOf(0x02, 0x30, 0x00) +
                s.copyOfRange(1, 48),
            RawSignature.toDer(r + s),
        )
    }

    @Test
    fun `a SEQUENCE of 128 content bytes or more takes the long length form`() {
        // P-521: two 67-byte INTEGERs, 138 bytes of content.
        assertContentEquals(
            byteArrayOf(0x30, 0x81.toByte(), 0x8A.toByte(), 0x02, 0x43, 0x00) + half(0x80, size = 66) +
                byteArrayOf(0x02, 0x43, 0x00) + half(0x81, size = 66),
            RawSignature.toDer(half(0x80, size = 66) + half(0x81, size = 66)),
        )
        // 127 bytes of content (INTEGERs of 62 and 61 bytes) keep the short form; 128 (63 and 61) take 0x81.
        val short = RawSignature.toDer(half(0x7F, size = 62) + byteArrayOf(0) + half(0x7F, size = 61))
        assertContentEquals(byteArrayOf(0x30, 0x7F), short.copyOf(2))
        assertEquals(129, short.size)
        val long = RawSignature.toDer(half(0x80, size = 62) + byteArrayOf(0) + half(0x7F, size = 61))
        assertContentEquals(byteArrayOf(0x30, 0x81.toByte(), 0x80.toByte()), long.copyOf(3))
        assertEquals(131, long.size)
    }

    @Test
    fun `zero is the single byte 00, in any pair length`() {
        assertContentEquals(hex("3006020100020100"), RawSignature.toDer(ByteArray(96)))
        assertContentEquals(hex("3006020100020100"), RawSignature.toDer(ByteArray(2)))
        val one =
            ByteArray(96).also {
                it[47] = 1
                it[95] = 0x80.toByte()
            }
        assertContentEquals(hex("300702010102020080"), RawSignature.toDer(one))
    }

    @Test
    fun `toDer takes an even 2 to 132 bytes only`() {
        for (size in listOf(0, 1, 95, 133, 134)) {
            assertFailsWith<IllegalArgumentException> { RawSignature.toDer(ByteArray(size)) }
        }
    }

    @Test
    fun `the JDK's DER form of its own P1363 signature is toDer's, on each curve`() {
        for ((curve, size) in listOf("secp256r1" to 64, "secp384r1" to 96, "secp521r1" to 132)) {
            val key = JcaFixtures.ec(curve)
            var leadingZero = false
            var highBit = false
            var n = 0
            // About one signature in 128 has a zero first byte in r or s: sign until both cases have occurred.
            while (!(leadingZero && highBit)) {
                check(++n <= 5000) { "$curve: no leading-zero and high-bit r or s in 5000 signatures" }
                val message = "message $n".encodeToByteArray()
                val raw = JcaFixtures.sign("SHA384withECDSAinP1363Format", key.private, message)
                assertEquals(size, raw.size, curve)
                val der = RawSignature.toDer(raw)
                val jdk =
                    Signature.getInstance("SHA384withECDSA").apply {
                        initVerify(key.public)
                        update(message)
                    }
                assertTrue(jdk.verify(der), "$curve signature $n")
                assertContentEquals(expected(raw), der, "$curve signature $n")
                assertContentEquals(raw, RawSignature.decode(url.encodeToString(raw)), "$curve signature $n text")
                val h = size / 2
                leadingZero = leadingZero || raw[0] == 0.toByte() || raw[h] == 0.toByte()
                // P-521's 66-byte halves begin with 0x00 or 0x01 (its order has 521 bits): there, a set high bit is
                // the first byte after one leading zero.
                highBit = highBit || raw[0] < 0 || raw[h] < 0 || (raw[0] == 0.toByte() && raw[1] < 0)
            }
        }
    }

    /** The DER of [raw] by `BigInteger.toByteArray()`, which is the minimal two's-complement encoding. */
    private fun expected(raw: ByteArray): ByteArray {
        val r = BigInteger(1, raw.copyOfRange(0, raw.size / 2)).toByteArray()
        val s = BigInteger(1, raw.copyOfRange(raw.size / 2, raw.size)).toByteArray()
        val content = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        val length =
            if (content.size < 0x80) {
                byteArrayOf(content.size.toByte())
            } else {
                byteArrayOf(0x81.toByte(), content.size.toByte())
            }
        return byteArrayOf(0x30) + length + content
    }
}
