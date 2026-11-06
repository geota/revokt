// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.RevoktLimits
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** The x5u PEM reader (spec §7.1 "x5u chain", §6.5 `x5u.pem`): lenient outside a block, strict base64 inside, the cap first. */
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
    fun `LF, CR and CRLF line endings, mixed or missing at the end, are accepted`() {
        val lf = X5uPemFixtures.pem(leaf, intermediate)
        val both = listOf(leaf, intermediate)
        assertDers(both, ders(lf.replace("\n", "\r\n")))
        assertDers(both, ders(lf.replace("\n", "\r")))
        assertDers(both, ders(lf.replaceFirst("\n", "\r\n").replaceFirst("\n", "\r")))
        assertDers(both, ders(lf.dropLast(1)))
        assertDers(both, ders(lf.replace("\n", "\r\n").dropLast(2)))
        assertDers(both, ders(lf.dropLast(1) + "\r"))
    }

    @Test
    fun `text, blank lines and other blocks outside a CERTIFICATE block are skipped`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        val both = listOf(leaf, intermediate)
        val blocks = pem.split("-----END CERTIFICATE-----\n").map { it + "-----END CERTIFICATE-----\n" }
        assertDers(both, ders(pem + "trailing text\n"))
        assertDers(both, ders(pem + "\n\n"))
        assertDers(both, ders(pem + " "))
        assertDers(both, ders("subject=CN=leaf\nissuer=CN=intermediate\n\n$pem"))
        assertDers(both, ders(blocks[0] + "\n\r\n" + blocks[1]))
        assertDers(both, ders("-----END CERTIFICATE-----\n$pem-----END CERTIFICATE-----\n"))
        val key = X5uPemFixtures.pem(root).replace("CERTIFICATE", "PUBLIC KEY")
        assertDers(both, ders(blocks[0] + key + blocks[1]))
        // A boundary that is not exact starts no block, so its block is skipped as text (as Firefox skips it).
        val bom = Char(0xFEFF)
        assertDers(listOf(intermediate), ders("$bom$pem"))
        assertDers(
            listOf(intermediate),
            ders(pem.replaceFirst("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----x")),
        )
        assertDers(
            listOf(intermediate),
            ders(pem.replaceFirst("-----BEGIN CERTIFICATE-----", " -----BEGIN CERTIFICATE-----")),
        )
        assertDers(listOf(intermediate), ders(pem.replaceFirst("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE")))
        assertDers(listOf(intermediate), ders(pem.replaceFirst("BEGIN CERTIFICATE", "BEGIN CERTIFICATX")))
    }

    @Test
    fun `spaces after BEGIN and anything after END on its line are allowed, as rustls-pki-types allows them`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        val both = listOf(leaf, intermediate)
        assertDers(both, ders(pem.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----   ")))
        assertDers(both, ders(pem.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE----- ")))
        assertDers(both, ders(pem.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----trailing text")))
        // A tab after BEGIN is not a space.
        assertDers(
            listOf(intermediate),
            ders(pem.replaceFirst("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\t")),
        )
    }

    @Test
    fun `no block, an empty block and an unterminated block are framing failures`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        assertEquals(X5uPemFailure.FRAMING, failure(""))
        assertEquals(X5uPemFailure.FRAMING, failure("\n\r\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("trailing text\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("-----END CERTIFICATE-----\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("CERTIFICATE", "PUBLIC KEY")))
        assertEquals(X5uPemFailure.FRAMING, failure("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("-----BEGIN CERTIFICATE-----\n\n\r\n-----END CERTIFICATE-----\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.substringBeforeLast("-----END CERTIFICATE-----")))
        // An END that is not exact does not end the block.
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("END CERTIFICATE", "END X509 CERTIFICATE")))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("END CERTIFICATE", "END CERTIFICATX")))
        assertEquals(
            X5uPemFailure.FRAMING,
            failure(pem.replace("-----END CERTIFICATE-----", " -----END CERTIFICATE-----")),
        )
        // A boundary cut short by the end of the body.
        assertEquals(X5uPemFailure.FRAMING, failure("-----BEGIN CERT"))
        assertEquals(
            X5uPemFailure.FRAMING,
            failure(pem.substringBeforeLast("-----END CERTIFICATE-----") + "-----END CERT"),
        )
        // A block of whitespace only is empty.
        assertEquals(X5uPemFailure.FRAMING, failure("-----BEGIN CERTIFICATE-----\n \t \n-----END CERTIFICATE-----\n"))
    }

    @Test
    fun `inside a block, lines of any length join into one canonical base64 text`() {
        val pem = X5uPemFixtures.pem(leaf)
        val lines = pem.lines()
        val begin = lines.first()
        val end = lines[lines.size - 2]

        fun with(body: List<String>) = (listOf(begin) + body + end).joinToString("\n", postfix = "\n")
        val body = lines.subList(1, lines.size - 2)
        val joined = body.joinToString("")
        // Rewrapped at 76 (MIME), at 60, at 1 and unwrapped; blank lines inside; padding split across lines.
        for (wrapped in listOf(joined.chunked(76), joined.chunked(60), joined.chunked(1), listOf(joined))) {
            assertDers(listOf(leaf), ders(with(wrapped)))
        }
        assertDers(listOf(leaf), ders(with(listOf("") + body + "")))
        assertDers(listOf(ByteArray(1)), ders(with(listOf("AA=", "="))))
        assertDers(listOf(ByteArray(1)), ders(with(listOf("A", "A", "==", ""))))
        // A text whose length is not a multiple of 4, padding inside, a pad character too many.
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf(joined.dropLast(1)))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf(joined.dropLast(2)))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA==", "AAAA"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("A=AA"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("A==="))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("===="))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("="))))
        // Non-zero bits after the last octet: "AA==" is the one spelling of 00, "AB==" is not; likewise "AAA=" and "AAB=".
        assertDers(listOf(ByteArray(1)), ders(with(listOf("AA=="))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AB=="))))
        assertDers(listOf(ByteArray(2)), ders(with(listOf("AAA="))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AAB="))))
        // The URL-safe alphabet, whitespace, a NUL, a non-ASCII octet, a header line and a nested BEGIN.
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA-_"))))
        // Whitespace inside the base64 is skipped: space, HT, VT, FF (rustls-pki-types' set).
        val vt = Char(0x0b)
        val ff = Char(0x0c)
        assertDers(listOf(ByteArray(2)), ders(with(listOf(" A A\tA= ", "$vt$ff"))))
        assertDers(listOf(leaf), ders(with(body.map { " $it\t" })))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA A"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AAé"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("AA\u0000A"))))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf("Proc-Type: 4,ENCRYPTED") + body)))
        assertEquals(X5uPemFailure.BASE64, failure(with(listOf(begin) + body)))
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
