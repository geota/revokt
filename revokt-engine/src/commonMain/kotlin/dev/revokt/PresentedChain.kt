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
 * The presented chain as an exemption reads it (spec §4): per certificate, leaf at index 0, the fields revokt's own
 * parser read from it. Every field is read once, when the chain is built, so the chain is plain data. A value type:
 * equality is by content (the certificates' bytes, which determine every field), and `ByteArray` getters return fresh
 * copies. An index outside `0 until size` throws `IndexOutOfBoundsException`.
 */
@OptIn(RevoktTestingApi::class)
public class PresentedChain private constructor(
    certificates: List<ParsedCertificate>,
) {
    private val entries: List<Entry> = buildList { certificates.forEach { add(Entry(it)) } }

    public val size: Int get() = entries.size

    /** Certificate [i]'s bytes as read (§5.3). A fresh copy. */
    public fun der(i: Int): ByteArray = entries[i].der.toByteArray()

    /** Certificate [i]'s subject `Name` TLV as encoded. A fresh copy. */
    public fun subject(i: Int): ByteArray = entries[i].subject.toByteArray()

    /** Certificate [i]'s issuer `Name` TLV as encoded. A fresh copy. */
    public fun issuer(i: Int): ByteArray = entries[i].issuer.toByteArray()

    /** The SHA-256 of certificate [i]'s `SubjectPublicKeyInfo` TLV. A fresh copy. */
    public fun spkiSha256(i: Int): ByteArray = entries[i].spkiSha256.toByteArray()

    /** Certificate [i]'s raw serial: the INTEGER content as encoded, sign byte and leading zeros kept. A fresh copy. */
    public fun serial(i: Int): ByteArray = entries[i].serial.toByteArray()

    /**
     * Certificate [i]'s `subjectAltName` `dNSName` entries, in certificate order, as the IA5String text encoded (ASCII):
     * raw, not checked as DNS syntax, and not normalised (case and any trailing dot kept). Empty when the certificate
     * has no SAN, and when its SAN does not read (malformed, or the extension twice): an exemption only lifts a fired
     * rule, so a name that cannot be read matches nothing.
     */
    public fun dnsNames(i: Int): List<String> = entries[i].dnsNames

    /** A builder holding this chain's certificates. */
    @RevoktTestingApi
    public fun newBuilder(): Builder = Builder().certificates(entries.map { it.der.toByteArray() })

    override fun equals(other: Any?): Boolean =
        other is PresentedChain && entries.map { it.der } == other.entries.map { it.der }

    override fun hashCode(): Int = entries.map { it.der }.hashCode()

    // A certificate prints as the SHA-256 of its DER.
    override fun toString(): String = "PresentedChain(certificates=${entries.map { it.der.sha256().hex() }})"

    /** One certificate's fields, read from its one parse. */
    private class Entry(
        p: ParsedCertificate,
    ) {
        val der: ByteString = p.der.toByteString()
        val subject: ByteString = p.rawSubject().toByteString()
        val issuer: ByteString = p.rawIssuer().toByteString()
        val spkiSha256: ByteString = p.rawSpki().toByteString().sha256()
        val serial: ByteString = p.rawSerial().toByteString()
        val dnsNames: List<String> =
            when (val san = ExtensionValues.subjectAltName(p)) {
                is ExtensionRead.Value -> buildList { addAll(san.value.dnsNames) }
                is ExtensionRead.Absent, is ExtensionRead.Failed -> emptyList()
            }
    }

    /** Builds a [PresentedChain] for tests and fakes from certificate DERs, leaf first; each must parse. */
    @RevoktTestingApi
    public class Builder {
        internal var certificates: List<ByteString> = emptyList()
            private set

        /** Replaces the certificates with copies of [ders], leaf first. */
        public fun certificates(ders: List<ByteArray>): Builder =
            apply { certificates = buildList { ders.forEach { add(it.toByteString()) } } }

        /** Parses each certificate; throws `IllegalArgumentException` naming the first that revokt's parser rejects. */
        public fun build(): PresentedChain =
            PresentedChain(
                certificates.mapIndexed { i, der ->
                    when (val r = CertificateParser.parse(der.toByteArray())) {
                        is CertificateParse.Parsed -> {
                            r.certificate
                        }

                        is CertificateParse.Failed -> {
                            throw IllegalArgumentException("certificate $i does not parse: ${r.reason} ${r.detail}")
                        }
                    }
                },
            )
    }

    internal companion object {
        /** The chain of [certificates], leaf first, each from the one parse the evaluation already made. */
        fun of(certificates: List<ParsedCertificate>): PresentedChain = PresentedChain(certificates)
    }
}
