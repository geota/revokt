// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.ParseReason
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.EnvelopeVariants
import dev.revokt.engine.parse.LengthForm
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.extension
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.TestDer.tlvWithLength

/**
 * The D7 leniency corpus of spec §9.2: each case the spec names, the replay inputs that carry it, and revokt's required
 * outcome where the spec states one (the SCT-list outcomes, the envelope re-encodings, the trailing-element rule and
 * the D8-gap examples); for every other case the corpus record is the record. Inputs the replay already holds for
 * another reason are named; the rest are built here as `d7/<name>`. Every case's inputs get a `D7_LENIENCY` record.
 */
internal object D7Corpus {
    /** revokt's required outcome: `Parsed` with [scts] SCTs and [keyable], or a [reason]; null fields are not asserted. */
    class Required(
        val reason: ParseReason? = null,
        val scts: Int? = null,
        val keyable: Boolean? = null,
        val sameAsBase: Boolean = false,
    ) {
        companion object {
            val STRUCTURE = Required(reason = ParseReason.STRUCTURE)

            fun parsed(
                scts: Int? = null,
                keyable: Boolean? = null,
            ) = Required(scts = scts, keyable = keyable)

            /** `Parsed` with the unmodified certificate's `producerKeyable` and key bytes (the envelope re-encodings). */
            val SAME_AS_BASE = Required(sameAsBase = true)
        }
    }

    /**
     * One D7 case. [firefox] marks an SCT case where Firefox's decoder fails the whole list while revokt extracts pairs
     * (§9.2 D3: version ≠ 0, trailing bytes in the OCTET STRING, an item length error), hand-recorded as a
     * `FIREFOX_SCT_STRICT` divergence.
     */
    class Case(
        val text: String,
        val inputs: List<String>,
        val required: Required? = null,
        val firefox: Boolean = false,
    )

    /** The divergence class of a [Case.firefox] case's inputs. */
    const val FIREFOX = "FIREFOX_SCT_STRICT"

    private const val SCT = "1.3.6.1.4.1.11129.2.4.2"

    private fun u16(n: Int) = bytes(n shr 8, n and 0xff)

    /** One SCT list item: [version], a 32-octet log id, the timestamp, no extensions, the algorithms and a [signature]. */
    private fun item(
        timestamp: Long,
        version: Int = 0,
        signature: ByteArray = bytes(0x30, 0x00),
        trailing: ByteArray = ByteArray(0),
    ): ByteArray {
        val body =
            bytes(version) + ByteArray(32) { 0x22 } + ByteArray(8) { (timestamp ushr (56 - 8 * it)).toByte() } +
                u16(0) + bytes(4, 3) + u16(signature.size) + signature + trailing
        return u16(body.size) + body
    }

    /** A `SignedCertificateTimestampList`: its u16 length ([declared], by default the items' size), the items, [trailing]. */
    private fun list(
        vararg items: ByteArray,
        declared: Int? = null,
        trailing: ByteArray = ByteArray(0),
    ): ByteArray {
        val content = items.fold(ByteArray(0)) { acc, b -> acc + b }
        return u16(declared ?: content.size) + content + trailing
    }

    private fun withSct(value: ByteArray) = BoundaryCorpus.base(extensions = listOf(extension(SCT, value)))

    /**
     * The boundary corpus's valid P-256 key, for every input built on [TestCert], whose default key is not a point: a
     * platform would reject the input for its key before reaching the case.
     */
    val key: ByteArray by lazy {
        DerNode.parse(BoundaryCorpus.base()).child(0, 6).let { DerNode(it.tag, it.content, null).encode() }
    }

    private fun withTimes(
        notBefore: ByteArray,
        notAfter: ByteArray,
    ) = BoundaryCorpus.base(validity = seq(notBefore, notAfter))

    private fun utc(s: String) = tlv(0x17, ascii(s))

    private fun gen(s: String) = tlv(0x18, ascii(s))

    private fun subject(value: ByteArray) = BoundaryCorpus.base(subject = seq(tlv(0x31, seq(oid("2.5.4.3"), value))))

    /** [der] with its TBS replaced by [tbs] (raw), in [form]. */
    private fun withTbs(
        der: ByteArray,
        tbs: ByteArray,
        form: LengthForm,
    ): ByteArray {
        val cert = DerNode.parse(der)
        cert.children!![0] = DerNode(0x30, tbs, null, form)
        return cert.encode()
    }

    /** The SCT-list cases built here. */
    private fun sctInputs(): List<Pair<String, ByteArray>> {
        val one = list(item(1))
        return listOf(
            "sct-declared-longer" to withSct(tlv(0x04, list(item(2), declared = item(2).size + 1))),
            "sct-declared-shorter" to withSct(tlv(0x04, list(item(3), item(4), declared = item(3).size))),
            "sct-first-malformed" to withSct(tlv(0x04, list(u16(3) + bytes(0, 1, 2), item(5)))),
            "sct-inner-84" to withSct(tlvWithLength(0x04, bytes(0x84, 0, 0, 0, one.size), one)),
            "sct-inner-ff" to withSct(tlvWithLength(0x04, bytes(0xff), one)),
            "sct-version-1" to withSct(tlv(0x04, list(item(6, version = 1)))),
            "sct-truncated-last" to withSct(tlv(0x04, list(item(7), item(8).copyOfRange(0, item(8).size - 1)))),
            "sct-trailing-after-inner" to withSct(tlv(0x04, list(item(9))) + bytes(0x05, 0x00)),
            "sct-trailing-after-list" to withSct(tlv(0x04, list(item(10), trailing = bytes(0xff, 0xff)))),
            "sct-trailing-in-item" to withSct(tlv(0x04, list(item(11, trailing = bytes(0xee))))),
            // An SCT extension after the Extensions SEQUENCE inside [3], where the read skips bytes unparsed.
            "sct-in-ignored-bytes" to
                TestCert(
                    spki = key,
                    extensionsWrapper = { exts ->
                        tlv(0xa3, seq(*exts.toTypedArray()), extension(SCT, tlv(0x04, list(item(12)))))
                    },
                ).der,
        )
    }

    /** The time cases built here. */
    private fun timeInputs(): List<Pair<String, ByteArray>> =
        listOf(
            "gentime-fraction" to withTimes(utc("261022134530Z"), gen("20500101000000.5Z")),
            "utctime-2050" to withTimes(utc("261022134530Z"), utc("500101000000Z")),
            "time-offset" to withTimes(utc("261022134530+0100"), gen("20500101000000Z")),
            "time-offset-negative" to withTimes(utc("261022134530-0130"), gen("20500101000000Z")),
            "gentime-offset" to withTimes(utc("261022134530Z"), gen("20500101000000+0100")),
            "time-no-seconds" to withTimes(utc("2610221345Z"), gen("20500101000000Z")),
            "time-feb-31" to withTimes(utc("260231000000Z"), gen("20500101000000Z")),
        )

    /** The inputs built here, as `d7/<name>`. */
    fun inputs(): List<Pair<String, ByteArray>> {
        val leaf = ProducerCorpus.resource("certs/letsencrypt.org-1.der")
        val leafTbs = DerNode.parse(leaf).child(0)
        val trailingTbs =
            leafTbs.encode().let { it.copyOfRange(it.size - leafTbs.content.size, it.size) } +
                bytes(0x9f, 0x01, 0x02, 0x05, 0x00)
        val built =
            sctInputs() + timeInputs() +
                listOf(
                    "name-printable" to subject(tlv(0x13, ascii("leaf.example"))),
                    "name-teletex" to subject(tlv(0x14, ascii("t61"))),
                    "name-bmp" to subject(tlv(0x1e, bytes(0, 0x41))),
                    "empty-subject" to BoundaryCorpus.base(subject = seq()),
                    // The form CAs issue: an empty subject with a critical subjectAltName (RFC 5280 §4.2.1.6).
                    "empty-subject-san" to
                        BoundaryCorpus.base(
                            subject = seq(),
                            extensions =
                                listOf(
                                    extension("2.5.29.17", seq(tlv(0x82, ascii("leaf.example"))), critical = true),
                                ),
                        ),
                    "duplicate-ski" to
                        BoundaryCorpus.base(
                            extensions =
                                listOf(
                                    extension("2.5.29.14", tlv(0x04, bytes(1, 2, 3, 4))),
                                    extension("2.5.29.14", tlv(0x04, bytes(5, 6, 7, 8))),
                                ),
                        ),
                    "stop-9f01" to TestCert(spki = key, uniqueIds = bytes(0x9f, 0x01, 0x01, 0x00)).der,
                    "stop-bf02" to TestCert(spki = key, uniqueIds = bytes(0xbf, 0x02, 0x01, 0x00)).der,
                    "stop-9f1f" to TestCert(spki = key, uniqueIds = bytes(0x9f, 0x1f, 0x1f) + ByteArray(31)).der,
                    "version-trailing-null" to
                        TestCert(spki = key, version = tlv(0xa0, tlv(0x02, bytes(2)), tlv(0x05))).der,
                    "ext3-83-00" to TestCert(spki = key, extensions = emptyList(), tbsTrailing = bytes(0x83, 0x00)).der,
                    "uid-a1-then-ext3-long" to
                        TestCert(
                            spki = key,
                            uniqueIds = tlv(0xa1, tlv(0x03, bytes(0, 0x55))),
                            extensionsWrapper = { exts ->
                                val list = seq(*exts.toTypedArray())
                                tlvWithLength(0xa3, bytes(0x81, list.size), list)
                            },
                        ).der,
                    "v1-with-extensions" to TestCert(spki = key, version = ByteArray(0)).der,
                    "v1-with-unique-id" to
                        TestCert(
                            spki = key,
                            version = ByteArray(0),
                            uniqueIds = tlv(0x81, bytes(0, 0x55)),
                            extensions = emptyList(),
                        ).der,
                    "v2-with-extensions" to TestCert(spki = key, version = tlv(0xa0, tlv(0x02, bytes(1)))).der,
                    "uid-not-bit-string" to TestCert(spki = key, uniqueIds = tlv(0x81, bytes(0x08, 0x55))).der,
                    "extension-64k" to
                        BoundaryCorpus.base(
                            extensions = listOf(extension("1.3.6.1.4.1.99999.4", ByteArray(65_536) { 0x5a })),
                        ),
                    "sig-indefinite-raw" to
                        DerNode.parse(leaf).let { c ->
                            val bits = c.child(2).content
                            c.children!![2] = DerNode(0x03, bits, null, LengthForm.Indefinite)
                            c.encode()
                        },
                    "trailing-9f01-definite" to withTbs(leaf, trailingTbs, LengthForm.Minimal),
                    "trailing-9f01-indefinite" to withTbs(leaf, trailingTbs, LengthForm.Indefinite),
                )
        return built.map { (name, der) -> "d7/$name" to der }
    }

    private val leaves = ProducerCorpus.envelopeLeaves

    /** The two TBS header forms the replay holds as `unsigned/` (the same bytes as the envelope's). */
    private val UNSIGNED = setOf("tbs-long-leading-zero", "tbs-indefinite")

    private fun envelope(
        variant: String,
        rsaOnly: Boolean = false,
    ) = leaves.filter { (_, rsa) -> rsa || !rsaOnly }.map { (leaf, _) -> "envelope/$leaf/$variant" }

    /**
     * The re-encodings §9.2 requires to read as the unmodified certificate (EnvelopeVariants, `SAME_AS_BASE`), named as
     * the replay holds them.
     */
    private val sameAsBase: List<String> =
        leaves.flatMap { (leaf, rsa) ->
            EnvelopeVariants.of(rsa).filter { it.expected == EnvelopeVariants.Expected.SAME_AS_BASE }.map {
                if (it.name in UNSIGNED) "unsigned/$leaf/${it.name}" else "envelope/$leaf/${it.name}"
            }
        }

    val cases: List<Case> =
        listOf(
            Case("a negative serial", listOf("boundary/negative-serial")),
            Case("a serial over 20 bytes", listOf("boundary/21-octet-serial")),
            Case("a serial with leading zeros", listOf("boundary/reject-serial-non-minimal")),
            Case("a TBS/outer algorithm mismatch (NULL vs absent)", envelope("alg-null-flipped")),
            Case("a GeneralizedTime with fractional seconds", listOf("d7/gentime-fraction")),
            Case("a UTCTime used for a date in 2050 or later", listOf("d7/utctime-2050")),
            Case(
                "PrintableString, UTF8String, TeletexString and BMPString names",
                listOf("d7/name-printable", "boundary/base", "d7/name-teletex", "d7/name-bmp"),
            ),
            Case("an empty subject", listOf("d7/empty-subject", "d7/empty-subject-san")),
            Case("duplicate extension OIDs", listOf("d7/duplicate-ski", "d3/sct-two-extensions")),
            Case(
                "two SCT extensions, an empty list first and a covered SCT second: the union is queried",
                listOf("d3/sct-two-extensions"),
                Required.parsed(scts = 1),
            ),
            Case("an unknown critical extension", listOf("boundary/critical-ff")),
            Case(
                "an SCT list whose declared length is longer than its content: the list fails",
                listOf("d7/sct-declared-longer"),
                Required.parsed(scts = 0),
            ),
            Case(
                "an SCT list whose declared length is shorter than its content: the items that fit are extracted",
                listOf("d7/sct-declared-shorter"),
                Required.parsed(scts = 1),
                firefox = true,
            ),
            Case(
                "a malformed first SCT followed by valid ones: the list fails",
                listOf("d7/sct-first-malformed"),
                Required.parsed(scts = 0),
            ),
            Case(
                "a non-minimal length on the SCT extension's inner OCTET STRING (81 nn with nn < 0x80, 84 00 00 " +
                    "00 nn): Parsed, the list's SCTs extracted, producerKeyable unaffected (the SCT extension is " +
                    "opaque, K1)",
                listOf("d3/sct-inner-81", "d7/sct-inner-84"),
                Required.parsed(scts = 1, keyable = true),
            ),
            Case(
                "an inner length 0x80 or 0xFF: the list fails",
                listOf("d3/sct-inner-80", "d7/sct-inner-ff"),
                Required.parsed(scts = 0),
            ),
            Case(
                "an inner identifier other than 0x04 that is tag number 4 (0x44, 1F 04): no pairs (3A_HEADER_LAX)",
                listOf("d3/sct-inner-44", "d3/sct-inner-1f04"),
                Required.parsed(scts = 0),
            ),
            Case(
                "a constructed inner OCTET STRING: the list fails",
                listOf("d3/sct-constructed-inner"),
                Required.parsed(scts = 0),
            ),
            Case(
                "a non-zero SCT version: extracted",
                listOf("d7/sct-version-1"),
                Required.parsed(scts = 1),
                firefox = true,
            ),
            Case(
                "a truncated last SCT: the items before it are extracted",
                listOf("d7/sct-truncated-last"),
                Required.parsed(scts = 1),
                firefox = true,
            ),
            Case(
                "trailing bytes after the inner OCTET STRING, after the declared list region and inside an SCT " +
                    "after its signature: ignored",
                listOf("d7/sct-trailing-after-inner", "d7/sct-trailing-after-list", "d7/sct-trailing-in-item"),
                Required.parsed(scts = 1),
                firefox = true,
            ),
            Case(
                "an SCT hidden in ignored bytes: never extracted",
                listOf("d7/sct-in-ignored-bytes"),
                Required.parsed(scts = 0),
            ),
            Case("a zero-length SCT signature: extracted", listOf("d3/sct-inner-04"), Required.parsed(scts = 1)),
            Case(
                "an inner identifier that is not tag number 4, such as 0x30: the list fails in revokt and 3a " +
                    "alike",
                listOf("d3/sct-inner-30"),
                Required.parsed(scts = 0),
            ),
            // The ignored-element cases: Parsed, and outside the profile since every ignored element is (K2).
            Case(
                "bytes after [3]: ignored",
                listOf("variants/tbs-junk-after-extensions", "variants/tbs-null-after-extensions"),
                Required.parsed(keyable = false),
            ),
            Case(
                "an element between subjectPublicKeyInfo and [3], dropping the extensions",
                listOf("variants/tbs-null-before-extensions", "variants/spki-then-null-then-uid"),
                Required.parsed(keyable = false),
            ),
            Case(
                "[2] before [1] and [1] twice, dropping them",
                listOf("variants/uid-82-then-81", "variants/uid-81-twice"),
                Required.parsed(keyable = false),
            ),
            Case("a constructed [1] or [2]", listOf("variants/uid-constructed-a1", "variants/uid-a2-constructed")),
            Case(
                "a primitive [3]: ignored",
                listOf("d3/primitive-3", "variants/ext3-primitive-83"),
                Required.parsed(keyable = false),
            ),
            Case(
                "an element with tag number 3 in another class or form holding an Extensions SEQUENCE (03, 23, " +
                    "43, 63, C3, E3): ignored, Parsed and outside the profile (K2), 3A_TBS_LAX",
                listOf(0x03, 0x23, 0x43, 0x63, 0xc3, 0xe3).map { "d3/tag3-%02x".format(it) },
                Required.parsed(keyable = false),
            ),
            Case(
                "a stop element with a multi-octet identifier (9f 03 or bf 03 holding the Extensions SEQUENCE; " +
                    "9f 01 01 00, bf 02 01 00, or 9f 1f and 31 octets, before [3]): STRUCTURE",
                listOf("d3/tag3-9f03", "d3/tag3-bf03", "d7/stop-9f01", "d7/stop-bf02", "d7/stop-9f1f"),
                Required.STRUCTURE,
            ),
            Case("two [3], the second ignored", listOf("variants/tbs-two-ext3"), Required.parsed(keyable = false)),
            Case(
                "bytes after the Extensions SEQUENCE inside [3] and after extnValue: ignored",
                listOf("variants/ext3-null-after-sequence", "variants/extension-null-after-extnvalue"),
                Required.parsed(keyable = false),
            ),
            Case(
                "anything after the INTEGER inside [0]: STRUCTURE (the producer flattens [0] and keys other " +
                    "bytes)",
                listOf("variants/version-wrapper-trailing", "d7/version-trailing-null"),
                Required.STRUCTURE,
            ),
            Case(
                "a zero-length primitive [3] (83 00): Parsed and outside the profile",
                listOf("d7/ext3-83-00"),
                Required.parsed(keyable = false),
            ),
            Case(
                "a constructed [1] then [3] carrying a non-minimal length: Parsed and outside the profile (K2), " +
                    "a D8-gap entry because ct-go never visits [3] there and keys it",
                listOf("d7/uid-a1-then-ext3-long"),
                Required.parsed(keyable = false),
            ),
            Case(
                "a v1 or v2 certificate carrying elements its version does not allow (more lenient than the JDK)",
                listOf("d7/v1-with-extensions", "d7/v1-with-unique-id", "d7/v2-with-extensions"),
            ),
            Case(
                "unique-id content that is not BIT STRING content (more lenient than the JDK)",
                listOf("d7/uid-not-bit-string"),
            ),
            Case(
                "times with an offset (UTCTime +0100 and -0130, a CONSCRYPT_TIME_OFFSET record against oracle 2; " +
                    "GeneralizedTime, which oracle 2 rejects), without seconds and with a day past the month's end " +
                    "(2026-02-31, rolling over to 2026-03-03)",
                listOf(
                    "d7/time-offset",
                    "d7/time-offset-negative",
                    "d7/gentime-offset",
                    "d7/time-no-seconds",
                    "d7/time-feb-31",
                ),
            ),
            Case("a 64 KB extension", listOf("d7/extension-64k")),
            Case(
                "BER indefinite lengths and non-minimal definite lengths",
                listOf(
                    "tbs-indefinite",
                    "tbs-long-leading-zero",
                    "tbs-long5",
                    "tbs-long8",
                ).map { "unsigned/letsencrypt.org-1/$it" } +
                    listOf("fuzz/indefinite", "boundary/reject-rsa-key-header-non-minimal"),
            ),
            Case(
                "a Certificate with trailing bytes",
                listOf("fuzz/trailing-byte", "variants/cert-null-after-signature"),
            ),
            Case(
                "the envelope re-encodings (non-minimal outer signatureAlgorithm and signatureValue headers, the " +
                    "outer NULL flipped, a non-zero RSA unused-bits octet with the padding bits clear and with them " +
                    "set, indefinite and non-minimal headers in the outer AlgorithmIdentifier, the TBS header " +
                    "long-form or indefinite, an indefinite TBS with indefinite children): Parsed with the " +
                    "unmodified certificate's producerKeyable and key bytes",
                sameAsBase,
                Required.SAME_AS_BASE,
            ),
            Case(
                "an indefinite TBS holding a non-minimal definite child (02 81 …, an SPKI 30 83 00 …), which the " +
                    "JDK accepts and fails to verify: STRUCTURE (oracle 1's read is Parsed through the platform " +
                    "canon)",
                envelope("tbs-indefinite-serial-81") + envelope("tbs-indefinite-serial-84") +
                    envelope("tbs-indefinite-spki-83"),
                Required.STRUCTURE,
            ),
            Case(
                "an indefinite outer AlgorithmIdentifier holding a non-minimal OID header (30 80 06 81 08 … 00 " +
                    "00), which the JDK rejects: STRUCTURE",
                envelope("alg-indefinite-oid-header-81"),
                Required.STRUCTURE,
            ),
            Case(
                "an indefinite signatureValue (03 80 <content> 00 00), whether or not its content reads as a " +
                    "chain of minimal TLVs, which JDK 17 and later reject: STRUCTURE",
                listOf("envelope/letsencrypt.org-1/sig-indefinite-nested", "d7/sig-indefinite-raw"),
                Required.STRUCTURE,
            ),
            Case(
                "a CA-signed TBS whose extensions are followed by a trailing element with a multi-octet tag (9f " +
                    "01 02 05 00), with a definite and with an indefinite TBS header: Parsed, outside the profile " +
                    "under K2, the same outcome for both",
                listOf("d7/trailing-9f01-definite", "d7/trailing-9f01-indefinite"),
                Required.parsed(keyable = false),
            ),
            Case(
                "the D8-gap examples (a serial with non-minimal INTEGER content, a keyUsage only zcrypto " +
                    "accepts, a UTCTime without seconds): Parsed and outside the profile",
                listOf(
                    "boundary/reject-serial-non-minimal",
                    "boundary/reject-key-usage-03-00",
                    "boundary/reject-key-usage-03-01-05",
                    "d7/time-no-seconds",
                ),
                Required.parsed(keyable = false),
            ),
        )

    /** The inputs built here that a case requires to be `STRUCTURE`. */
    val builtRejects: Set<String> by lazy {
        cases
            .filter { it.required?.reason == ParseReason.STRUCTURE }
            .flatMap { it.inputs }
            .filter {
                it.startsWith(
                    "d7/",
                )
            }.toSet()
    }

    /** The inputs of the [Case.firefox] cases. */
    val firefoxInputs: Set<String> by lazy { cases.filter { it.firefox }.flatMap { it.inputs }.toSet() }

    /** Each D7 input with the cases it carries, in [cases] order. */
    val byInput: Map<String, List<Case>> by lazy {
        val out = LinkedHashMap<String, MutableList<Case>>()
        for (c in cases) for (i in c.inputs) out.getOrPut(i) { ArrayList() } += c
        out
    }
}
