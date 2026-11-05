// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.RevoktLimits
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** The x5u PEM reader (spec §7.1 "x5u chain", §6.5 `x5u.pem`): strict RFC 7468 blocks, the cap first. */
class X5uPemTest {
    private val leaf = ByteArray(100) { it.toByte() }
    private val intermediate = ByteArray(47) { (it * 7).toByte() }
    private val root = ByteArray(1) { 0x30 }

    private fun ders(text: String): List<ByteArray> =
        assertIs<X5uPemRead.Certificates>(X5uPem.read(text.encodeToByteArray()), text).ders

    private fun failure(
        text: String,
        maxBytes: Long = RevoktLimits.MAX_X5U_BYTES,
    ): X5uPemFailure = assertIs<X5uPemRead.Failed>(X5uPem.read(text.encodeToByteArray(), maxBytes), text).reason

    private fun assertDers(
        expected: List<ByteArray>,
        actual: List<ByteArray>,
    ) {
        assertEquals(expected.size, actual.size)
        expected.zip(actual).forEach { (e, a) -> assertContentEquals(e, a) }
    }

    @Test
    fun `concatenated blocks read in order, leaf first`() {
        assertDers(listOf(leaf), ders(X5uPemFixtures.pem(leaf)))
        assertDers(listOf(leaf, intermediate, root), ders(X5uPemFixtures.pem(leaf, intermediate, root)))
        // A last line of exactly 64 characters, and of 4.
        assertDers(listOf(ByteArray(48)), ders(X5uPemFixtures.pem(ByteArray(48))))
        assertDers(listOf(ByteArray(51)), ders(X5uPemFixtures.pem(ByteArray(51))))
        assertDers(listOf(ByteArray(2)), ders(X5uPemFixtures.pem(ByteArray(2))))
    }

    @Test
    fun `CRLF, mixed line endings and a missing final line ending are accepted`() {
        val lf = X5uPemFixtures.pem(leaf, intermediate)
        assertDers(listOf(leaf, intermediate), ders(lf.replace("\n", "\r\n")))
        assertDers(listOf(leaf, intermediate), ders(lf.replaceFirst("\n", "\r\n")))
        assertDers(listOf(leaf, intermediate), ders(lf.dropLast(1)))
        assertDers(listOf(leaf, intermediate), ders(lf.replace("\n", "\r\n").dropLast(2)))
    }

    @Test
    fun `text before, between or after the blocks is a framing failure`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        val blocks = pem.split("-----END CERTIFICATE-----\n")
        assertEquals(X5uPemFailure.FRAMING, failure(pem + "trailing text\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(pem + "\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(pem + " "))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.dropLast(1) + "\r"))
        assertEquals(X5uPemFailure.FRAMING, failure("subject=CN=leaf\n$pem"))
        assertEquals(X5uPemFailure.FRAMING, failure("\n$pem"))
        // A byte order mark.
        assertEquals(X5uPemFailure.FRAMING, failure("\uFEFF$pem"))
        assertEquals(
            X5uPemFailure.FRAMING,
            failure(blocks[0] + "-----END CERTIFICATE-----\n\n" + blocks[1] + "-----END CERTIFICATE-----\n"),
        )
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE")))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("END CERTIFICATE", "END X509 CERTIFICATE")))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("BEGIN CERTIFICATE", "BEGIN CERTIFICATX")))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("END CERTIFICATE", "END CERTIFICATX")))
        assertEquals(
            X5uPemFailure.FRAMING,
            failure(pem.replaceFirst("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE----- ")),
        )
        assertEquals(
            X5uPemFailure.FRAMING,
            failure(pem.replaceFirst("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE----")),
        )
        assertEquals(X5uPemFailure.FRAMING, failure(blocks[0]))
        assertEquals(X5uPemFailure.FRAMING, failure("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(""))
        assertEquals(X5uPemFailure.FRAMING, failure("\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("-----END CERTIFICATE-----\n"))
    }

    @Test
    fun `base64 lines must be 64 characters but the last, canonical and padded only at the end`() {
        val pem = X5uPemFixtures.pem(leaf)
        val lines = pem.lines()

        val begin = lines.first()
        val end = lines[lines.size - 2]

        fun with(body: List<String>) = (listOf(begin) + body + end).joinToString("\n", postfix = "\n")
        val body = lines.subList(1, lines.size - 2)
        // Rewrapped at 76 (MIME) and at 60 columns.
        val joined = body.joinToString("")
        assertEquals(X5uPemFailure.BASE64, failure(with(joined.chunked(76))))
        assertEquals(X5uPemFailure.BASE64, failure(with(joined.chunked(60))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf(body[0] + "AAAA") + body.drop(1))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf(body[0] + "AAAA"))))
        // A last line that is not a whole quantum, one with padding inside, a pad character too many.
        assertEquals(X5uPemFailure.BASE64, failure(with(body.dropLast(1) + body.last().dropLast(1))))
        assertEquals(X5uPemFailure.BASE64, failure(with(body.dropLast(1) + "A=AA")))
        assertEquals(X5uPemFailure.BASE64, failure(with(body.dropLast(1) + "A===")))
        assertEquals(X5uPemFailure.BASE64, failure(with(body.dropLast(1) + "====")))
        assertEquals(X5uPemFailure.BASE64, failure(with(body.dropLast(1) + "AA")))
        // Non-zero bits after the last octet: "AA==" is the one spelling of 00, "AB==" is not; likewise "AAA=" and "AAB=".
        assertDers(listOf(ByteArray(1)), ders(with(listOf("AA=="))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AB=="))))
        assertDers(listOf(ByteArray(2)), ders(with(listOf("AAA="))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AAB="))))
        // The URL-safe alphabet, whitespace, a stray CR and a non-ASCII octet.
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA-_"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA A"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA\rA"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AAé"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA\u0000A"))))
        // A header line (RFC 1421) and a blank line inside a block.
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("Proc-Type: 4,ENCRYPTED") + body)))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("") + body)))
        assertEquals(X5uPemFailure.BASE64, failure(with(body + "")))
    }

    @Test
    fun `a body over the cap is rejected before decoding`() {
        val pem = X5uPemFixtures.pem(leaf)
        val size = pem.encodeToByteArray().size.toLong()
        assertDers(listOf(leaf), assertIs<X5uPemRead.Certificates>(X5uPem.read(pem.encodeToByteArray(), size)).ders)
        assertEquals(X5uPemFailure.OVERSIZE, failure(pem, size - 1))
        // Over the cap, even when nothing in it is a block.
        assertEquals(X5uPemFailure.OVERSIZE, failure("x".repeat(RevoktLimits.MAX_X5U_BYTES.toInt() + 1)))
        val atCap = X5uPemFixtures.pem(ByteArray(48_000))
        val atCapBytes = atCap.encodeToByteArray()
        assertEquals(true, atCapBytes.size <= RevoktLimits.MAX_X5U_BYTES)
        assertDers(listOf(ByteArray(48_000)), ders(atCap))
        val over = X5uPemFixtures.pem(ByteArray(48_000), ByteArray(1_000))
        assertEquals(true, over.encodeToByteArray().size > RevoktLimits.MAX_X5U_BYTES)
        assertEquals(X5uPemFailure.OVERSIZE, failure(over))
    }

    @Test
    fun `every byte value decodes through the alphabet`() {
        val all = ByteArray(256) { it.toByte() }
        assertDers(listOf(all), ders(X5uPemFixtures.pem(all)))
        val lines = X5uPemFixtures.pem(all).lines()
        assertEquals(all.toByteString().base64(), lines.subList(1, lines.size - 2).joinToString(""))
    }
}

/** Test-only PEM in the form Go's `pem.Encode` writes and Mozilla serves: LF line endings, 64 columns, a final LF. */
internal object X5uPemFixtures {
    fun pem(vararg ders: ByteArray): String =
        ders.joinToString("") { der ->
            val lines = der.toByteString().base64().chunked(64)
            (
                listOf(
                    "-----BEGIN CERTIFICATE-----",
                ) + lines + "-----END CERTIFICATE-----"
            ).joinToString("\n", postfix = "\n")
        }
}
