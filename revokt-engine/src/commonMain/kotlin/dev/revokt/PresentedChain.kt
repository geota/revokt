// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ExtensionRead
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * The presented chain as an exemption reads it (spec §4): every presented certificate, in presented order (the leaf at
 * index 0), so an index is the presented chain's, as `Finding.AlgorithmIdMismatch.certIndex` is. Each entry holds the
 * fields revokt's own parser read from it, read once when the chain is built, so the chain is plain data. A certificate
 * revokt did not parse (it rejected it, or the evaluation stopped before reading it) keeps its [der] and has [parsed]
 * false; its [subject], [issuer], [spkiSha256] and [serial] are empty arrays and its [dnsNames] empty, so nothing
 * matches it. A value type: equality is by each certificate's bytes and [parsed] flag, which determine every other
 * field, and `ByteArray` getters return fresh copies. An index outside `0 until size` throws
 * `IndexOutOfBoundsException`.
 */
@OptIn(RevoktTestingApi::class)
public class PresentedChain private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added.
    private val entries: List<Entry> =
        buildList {
            val parses = builder.parses
            require(parses == null || parses.size == builder.certificates.size) {
                "one parse result per certificate: ${builder.certificates.size} certificates, ${parses?.size} results"
            }
            builder.certificates.forEachIndexed { i, der ->
                val p =
                    when {
                        parses != null -> parses[i]
                        i in builder.unparsed -> null
                        else -> (CertificateParser.parse(der.toByteArray()) as? CertificateParse.Parsed)?.certificate
                    }
                require(p == null || (der.size == p.der.size && der.rangeEquals(0, p.der, 0, p.der.size))) {
                    "the parse result of certificate $i is of other bytes"
                }
                add(Entry(der, p))
            }
        }

    public val size: Int get() = entries.size

    /** Certificate [i]'s bytes as read (§5.3), whether or not revokt parsed it. A fresh copy. */
    public fun der(i: Int): ByteArray = entries[i].der.toByteArray()

    /**
     * True when revokt parsed certificate [i], so its other fields are read from it; false when they are empty because
     * it was not, which tells an unparsed certificate from one whose SAN has no `dNSName`.
     */
    public fun parsed(i: Int): Boolean = entries[i].parsed

    /** Certificate [i]'s subject `Name` TLV as encoded; empty when not [parsed]. A fresh copy. */
    public fun subject(i: Int): ByteArray = entries[i].subject.toByteArray()

    /** Certificate [i]'s issuer `Name` TLV as encoded; empty when not [parsed]. A fresh copy. */
    public fun issuer(i: Int): ByteArray = entries[i].issuer.toByteArray()

    /** The SHA-256 of certificate [i]'s `SubjectPublicKeyInfo` TLV; empty when not [parsed]. A fresh copy. */
    public fun spkiSha256(i: Int): ByteArray = entries[i].spkiSha256.toByteArray()

    /**
     * Certificate [i]'s raw serial: the INTEGER content as encoded, sign byte and leading zeros kept; empty when not
     * [parsed]. A fresh copy.
     */
    public fun serial(i: Int): ByteArray = entries[i].serial.toByteArray()

    /**
     * Certificate [i]'s `subjectAltName` `dNSName` entries, in certificate order, as the IA5String text encoded (ASCII):
     * raw, not checked as DNS syntax (control characters included) and not normalised (case and any trailing dot kept),
     * so match a name exactly, never by suffix on a raw name. Empty when the certificate has no SAN, when its SAN does
     * not read (malformed, a non-ASCII `dNSName`, or the extension twice) and when it is not [parsed]: an exemption only
     * lifts a fired rule, so a name that cannot be read matches nothing.
     */
    public fun dnsNames(i: Int): List<String> = entries[i].dnsNames

    /** A builder holding this chain's certificates, and which of them were not parsed. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .certificates(entries.map { it.der.toByteArray() })
            .unparsed(entries.indices.filterTo(HashSet()) { !entries[it].parsed })

    private fun key(): List<Pair<ByteString, Boolean>> = entries.map { it.der to it.parsed }

    override fun equals(other: Any?): Boolean = other is PresentedChain && key() == other.key()

    override fun hashCode(): Int = key().hashCode()

    // A certificate prints as the SHA-256 of its DER, marked when it was not parsed.
    override fun toString(): String =
        entries.joinToString(prefix = "PresentedChain(certificates=[", postfix = "])") {
            it.der.sha256().hex() + if (it.parsed) "" else " (not parsed)"
        }

    /** One certificate's fields, read from its one parse [p]; empty when there is none. */
    private class Entry(
        val der: ByteString,
        p: ParsedCertificate?,
    ) {
        val parsed: Boolean = p != null
        val subject: ByteString = p?.rawSubject()?.toByteString() ?: ByteString.EMPTY
        val issuer: ByteString = p?.rawIssuer()?.toByteString() ?: ByteString.EMPTY
        val spkiSha256: ByteString = p?.rawSpki()?.toByteString()?.sha256() ?: ByteString.EMPTY
        val serial: ByteString = p?.rawSerial()?.toByteString() ?: ByteString.EMPTY
        val dnsNames: List<String> =
            when (val san = p?.let { ExtensionValues.subjectAltName(it) }) {
                is ExtensionRead.Value -> buildList { addAll(san.value.dnsNames) }
                is ExtensionRead.Absent, is ExtensionRead.Failed, null -> emptyList()
            }
    }

    /**
     * Builds a [PresentedChain] for tests and fakes from certificate DERs, leaf first. [build] parses each with revokt's
     * parser; one it rejects is kept, not parsed.
     */
    @RevoktTestingApi
    public class Builder {
        internal var certificates: List<ByteString> = emptyList()
            private set
        internal var unparsed: Set<Int> = emptySet()
            private set
        internal var parses: List<ParsedCertificate?>? = null
            private set

        /** Replaces the certificates with copies of [ders], leaf first, and drops what was set about their parses. */
        public fun certificates(ders: List<ByteArray>): Builder =
            apply {
                certificates = buildList { ders.forEach { add(it.toByteString()) } }
                unparsed = emptySet()
                parses = null
            }

        /** The indices of certificates kept unparsed even if they would parse, as an evaluation that stopped early. */
        internal fun unparsed(indices: Set<Int>): Builder = apply { unparsed = buildSet { addAll(indices) } }

        /** The evaluation's parse of each certificate, in [certificates] order, null where it has none; set after it. */
        internal fun parses(parses: List<ParsedCertificate?>): Builder =
            apply {
                this.parses =
                    buildList { addAll(parses) }
            }

        public fun build(): PresentedChain = PresentedChain(this)
    }

    internal companion object {
        /**
         * The engine's chain (#133): every DER of [presented], in order, with the evaluation's parse of each from
         * [parses] (null where it rejected the certificate or did not read it), so nothing is parsed twice.
         */
        fun of(
            presented: List<ByteArray>,
            parses: List<ParsedCertificate?>,
        ): PresentedChain =
            Builder()
                .certificates(presented)
                .parses(parses)
                .build()
    }
}
