// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.RevoktLimits
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** The x5u PEM reader (spec §7.1 "x5u chain", §6.5 `x5u.pem`): `rustls-pki-types` 1.15.1's rules, the cap first. */
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
        assertDers(both, ders(lf.dropLast(1) + "\r"))
    }

    @Test
    fun `text, blank lines and blocks with other labels are skipped`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        val both = listOf(leaf, intermediate)
        val blocks = pem.split("-----END CERTIFICATE-----\n").map { it + "-----END CERTIFICATE-----\n" }
        assertDers(both, ders(pem + "trailing text\n\n"))
        assertDers(both, ders("subject=CN=leaf\n\n$pem"))
        assertDers(both, ders(blocks[0] + "\n\r\n" + blocks[1]))
        assertDers(both, ders("-----END CERTIFICATE-----\n$pem-----END CERTIFICATE-----\n"))
        // A known label (decoded, then dropped) and an unknown one (skipped undecoded, even when not base64).
        val key = X5uPemFixtures.pem(root).replace("CERTIFICATE", "PUBLIC KEY")
        assertDers(both, ders(blocks[0] + key + blocks[1]))
        assertDers(
            both,
            ders(
                blocks[0] + "-----BEGIN X509 CERTIFICATE-----\nnot base64!\n-----END X509 CERTIFICATE-----\n" +
                    blocks[1],
            ),
        )
        // A known label's base64 is decoded even though the block is dropped, so a bad one fails the body; an unknown
        // label's is not.
        val badKey = "-----BEGIN PUBLIC KEY-----\nnot base64!\n-----END PUBLIC KEY-----\n"
        assertEquals(X5uPemFailure.BASE64, failure(blocks[0] + badKey + blocks[1]))
        // A label is compared by its octets, a non-ASCII one included.
        assertDers(
            both,
            ders(blocks[0] + "-----BEGIN ÉTIQUETTE-----\nnot base64!\n-----END ÉTIQUETTE-----\n" + blocks[1]),
        )
        // A line that does not start with "-----BEGIN " opens nothing, so its block is skipped as text.
        val bom = Char(0xFEFF)
        assertDers(listOf(intermediate), ders("$bom$pem"))
        assertDers(
            listOf(intermediate),
            ders(pem.replaceFirst("-----BEGIN CERTIFICATE-----", " -----BEGIN CERTIFICATE-----")),
        )
        // A label other than exactly CERTIFICATE, a space before the dashes included, is another block.
        assertDers(listOf(intermediate), ders(blocks[0].replace("CERTIFICATE", "CERTIFICATX") + blocks[1]))
        assertDers(listOf(intermediate), ders(blocks[0].replace("CERTIFICATE-----", "CERTIFICATE -----") + blocks[1]))
        // Its END must name it: one that names CERTIFICATE leaves the block open, so the next BEGIN restarts it with the
        // END line as base64.
        assertEquals(X5uPemFailure.BASE64, failure(pem.replaceFirst("BEGIN CERTIFICATE", "BEGIN CERTIFICATX")))
    }

    @Test
    fun `a BEGIN line ends in five dashes, spaces allowed among and after them`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        val both = listOf(leaf, intermediate)
        for (begin in listOf(
            "-----BEGIN CERTIFICATE-----   ",
            "-----BEGIN CERTIFICATE--- --",
            "-----BEGIN CERTIFICATE- - - - - ",
        )) {
            assertDers(both, ders(pem.replace("-----BEGIN CERTIFICATE-----", begin)))
        }
        // Text after the dashes, four or six dashes, a tab: the line is malformed and the body fails, as in rustls.
        for (begin in listOf(
            "-----BEGIN CERTIFICATE-----x",
            "-----BEGIN CERTIFICATE----",
            "-----BEGIN CERTIFICATE------",
            "-----BEGIN CERTIFICATE-----\t",
            "-----BEGIN CERTIFICATE",
            "-----BEGIN ",
        )) {
            assertEquals(X5uPemFailure.FRAMING, failure(pem.replaceFirst("-----BEGIN CERTIFICATE-----", begin)), begin)
        }
        // A malformed BEGIN line of any label, or among the text, fails too.
        assertEquals(X5uPemFailure.FRAMING, failure(pem + "-----BEGIN PUBLIC KEY----\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("-----BEGIN comment\n$pem"))
        // An empty label is a label like any other.
        assertDers(both, ders("-----BEGIN -----\nx\n-----END -----\n$pem"))
    }

    @Test
    fun `a BEGIN line inside a block restarts it and keeps the base64 read so far`() {
        val text = (leaf + intermediate).toByteString().base64()
        val split = text.length / 2 / 4 * 4
        val (head, tail) = text.take(split) to text.drop(split)
        val begin = "-----BEGIN CERTIFICATE-----"
        val body = "$begin\n$head\n$begin\n$tail\n-----END CERTIFICATE-----\n"
        assertDers(listOf(leaf + intermediate), ders(body))
        // Restarted as another label, the block is skipped at that label's END.
        val other =
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----BEGIN OTHER-----\n-----END OTHER-----\n" + X5uPemFixtures.pem(root)
        assertDers(listOf(root), ders(other))
    }

    @Test
    fun `an END line names the block's label and may be followed by anything`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        val both = listOf(leaf, intermediate)
        assertDers(both, ders(pem.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE----- ")))
        assertDers(both, ders(pem.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----trailing text")))
        // Another label's END inside the block is base64, and not valid base64.
        assertEquals(
            X5uPemFailure.BASE64,
            failure(pem.replaceFirst("-----END CERTIFICATE-----", "-----END PUBLIC KEY-----")),
        )
        // An END that does not start the line, names another label or is short of dashes never ends a block, so the body
        // ends inside one.
        for (end in listOf(" -----END CERTIFICATE-----", "-----END CERTIFICATX-----", "-----END CERTIFICATE----")) {
            assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("-----END CERTIFICATE-----", end)), end)
        }
    }

    @Test
    fun `no CERTIFICATE block, and a block the body ends inside, are framing failures`() {
        val pem = X5uPemFixtures.pem(leaf, intermediate)
        assertEquals(X5uPemFailure.FRAMING, failure(""))
        assertEquals(X5uPemFailure.FRAMING, failure("\n\r\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("trailing text\n"))
        assertEquals(X5uPemFailure.FRAMING, failure("-----END CERTIFICATE-----\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.replace("CERTIFICATE", "PUBLIC KEY")))
        assertEquals(X5uPemFailure.FRAMING, failure(pem.substringBeforeLast("-----END CERTIFICATE-----")))
        assertEquals(
            X5uPemFailure.FRAMING,
            failure(pem.substringBeforeLast("-----END CERTIFICATE-----") + "-----END CERT"),
        )
        // A block of another label left open at the end fails too, as rustls' MissingSectionEnd does.
        assertEquals(X5uPemFailure.FRAMING, failure(pem + "-----BEGIN PUBLIC KEY-----\nAAAA\n"))
        assertEquals(X5uPemFailure.FRAMING, failure(pem + "-----BEGIN OTHER-----\n"))
    }

    @Test
    fun `an empty CERTIFICATE block reads as no octets, as rustls-pki-types reads it`() {
        val empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
        assertDers(listOf(ByteArray(0)), ders(empty))
        assertDers(
            listOf(ByteArray(0), leaf),
            ders(empty.replace("\n-----END", "\n \t\n-----END") + X5uPemFixtures.pem(leaf)),
        )
    }

    @Test
    fun `the base64 decoder is rustls-pki-types' decoder`() {
        fun block(vararg lines: String) =
            (listOf("-----BEGIN CERTIFICATE-----") + lines + "-----END CERTIFICATE-----").joinToString("\n")

        fun der(vararg lines: String) = ders(block(*lines)).single()

        val leafText = leaf.toByteString().base64()
        // Any line length, blank lines, whitespace (HT, LF, VT, FF, CR, space) anywhere, padding split across lines.
        for (wrapped in listOf(leafText.chunked(76), leafText.chunked(1), listOf(leafText))) {
            assertContentEquals(leaf, der(*wrapped.toTypedArray()))
        }
        val vt = Char(0x0b)
        val ff = Char(0x0c)
        assertContentEquals(ByteArray(2), der(" A A\tA= ", "$vt$ff"))
        assertContentEquals(ByteArray(1), der("AA=", "="))
        // Padding is optional, and the bits after the last octet are dropped unchecked.
        assertContentEquals(ByteArray(1), der("AA"))
        assertContentEquals(ByteArray(2), der("AAA"))
        assertContentEquals(ByteArray(1), der("AB=="))
        assertContentEquals(ByteArray(1), der("AP"))
        assertContentEquals(bytes(0, 0), der("AAB="))
        assertContentEquals(leaf, der(leafText.trimEnd('=')))
        assertContentEquals(ByteArray(6), der("AAAAAAAA"))
        assertContentEquals(ByteArray(4), der("AAAAAA"))
        assertContentEquals(ByteArray(5), der("AAAAAAA="))
        // A lone sextet, padding not at the end, a malformed last group.
        for (bad in listOf(
            "A",
            "AAAAA",
            "AA=",
            "A=",
            "=",
            "A===",
            "====",
            "A=AA",
            "AA==AAAA",
            "AAA=AAAA",
            "AAAA=",
            "AAAAAA=A",
        )) {
            assertEquals(X5uPemFailure.BASE64, failure(block(bad)), bad)
        }
        // The URL-safe alphabet, a NUL, a non-ASCII octet, a header line.
        for (bad in listOf("AA-_", "AA\u0000A", "AAé=", "Proc-Type: 4,ENCRYPTED")) {
            assertEquals(X5uPemFailure.BASE64, failure(block(bad)), bad)
        }
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

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
