// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.verify.JcaFixtures
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
 * for `SHA384withECDSA`"): the decoder's alphabet and length, and the conversion's minimal INTEGERs, against the JDK's
 * own P1363 and DER forms of one signature.
 */
class RawSignatureTest {
    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun half(
        first: Int,
        fill: Int = 0x11,
    ): ByteArray = ByteArray(48) { if (it == 0) first.toByte() else fill.toByte() }

    @Test
    fun `decode reads exactly 128 characters of the base64url alphabet`() {
        val raw = ByteArray(96) { (it * 37 + 5).toByte() }
        val text = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        assertEquals(128, text.length)
        assertContentEquals(raw, RawSignature.decode(text))
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val every = (alphabet + alphabet).take(128)
        assertContentEquals(Base64.getUrlDecoder().decode(every), RawSignature.decode(every))
        assertContentEquals(ByteArray(96), RawSignature.decode("A".repeat(128)))
        assertContentEquals(ByteArray(96) { -1 }, RawSignature.decode("_".repeat(128)))
    }

    @Test
    fun `decode rejects any other length or character`() {
        val text = "A".repeat(128)
        for (length in listOf(
            0,
            1,
            4,
            124,
            127,
            129,
            132,
        )) {
            assertNull(RawSignature.decode("A".repeat(length)), "$length")
        }
        val outside =
            (0..0x2FF).map { it.toChar() }.filter {
                it !in 'A'..'Z' && it !in 'a'..'z' && it !in '0'..'9' &&
                    it != '-' &&
                    it != '_'
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
    fun `zero is the single byte 00`() {
        assertContentEquals(hex("3006020100020100"), RawSignature.toDer(ByteArray(96)))
        val one =
            ByteArray(96).also {
                it[47] = 1
                it[95] = 0x80.toByte()
            }
        assertContentEquals(hex("300702010102020080"), RawSignature.toDer(one))
    }

    @Test
    fun `toDer takes 96 bytes only`() {
        for (size in listOf(0, 64, 95, 97, 132)) {
            assertFailsWith<IllegalArgumentException> {
                RawSignature.toDer(ByteArray(size))
            }
        }
    }

    @Test
    fun `the JDK's DER form of its own P1363 signature is toDer's`() {
        val key = JcaFixtures.ec("secp384r1")
        var leadingZero = false
        var highBit = false
        repeat(200) {
            val message = "message $it".encodeToByteArray()
            val raw = JcaFixtures.sign("SHA384withECDSAinP1363Format", key.private, message)
            val der = RawSignature.toDer(raw)
            val jdk =
                Signature.getInstance("SHA384withECDSA").apply {
                    initVerify(key.public)
                    update(message)
                }
            assertTrue(jdk.verify(der), "signature $it")
            assertContentEquals(der, expected(raw), "signature $it")
            leadingZero = leadingZero || raw[0] == 0.toByte() || raw[48] == 0.toByte()
            highBit = highBit || raw[0] < 0 || raw[48] < 0
        }
        assertTrue(highBit, "no high-bit r or s in 200 signatures")
        println("raw-to-DER: a leading-zero r or s among the 200 signatures: $leadingZero")
    }

    /** The DER of [raw] by `BigInteger.toByteArray()`, which is the minimal two's-complement encoding. */
    private fun expected(raw: ByteArray): ByteArray {
        val r = java.math.BigInteger(1, raw.copyOfRange(0, 48)).toByteArray()
        val s = java.math.BigInteger(1, raw.copyOfRange(48, 96)).toByteArray()
        return byteArrayOf(0x30, (r.size + s.size + 4).toByte(), 0x02, r.size.toByte()) + r +
            byteArrayOf(0x02, s.size.toByte()) +
            s
    }
}
