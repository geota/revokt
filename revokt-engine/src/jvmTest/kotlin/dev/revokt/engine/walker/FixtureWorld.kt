// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.testing.CertId
import dev.revokt.testing.KeyId
import dev.revokt.testing.SymKey
import dev.revokt.testing.SymOids
import dev.revokt.testing.SymVerifier
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** One certificate of a [FixtureWorld]: its [label] (for messages), DER, raw subject name and key. */
internal class FixtureCert(
    val label: String,
    val der: ByteArray,
    val tbs: ByteArray,
    val subject: ByteArray,
    val key: SymKey,
) {
    val bytesHash: ByteString = der.toByteString().sha256()
    val keyHash: ByteString get() = key.id.sha256

    override fun toString(): String = label
}

/**
 * The certificates and verifier links of one walker fixture (spec §9 walker schema), built from the §9.1 generator's
 * primitives: [SymKey] keys, and links the [SymVerifier] answers `VERIFIED` for. Every certificate is a v3
 * certificate whose fields the fixture chooses; a certificate is linked to its [cert] `signer`, and [verifies] adds a
 * link for any other key (an ECDSA-recovered or RSA duplicate-signature key, §9.1).
 */
internal class FixtureWorld {
    private var serials = 0
    private var keys = 0
    private val links = LinkedHashSet<Pair<CertId, KeyId>>()
    private val labels = HashMap<ByteString, String>()

    /** The `Validity` of the certificates [cert] issues; [withValidity] changes it for a block (a §9.2 K6 failure). */
    private var validity: ByteArray = TestCert().validity

    /** [block]'s certificates carry [v] as their `Validity`. */
    fun <T> withValidity(
        v: ByteArray,
        block: () -> T,
    ): T {
        val before = validity
        validity = v
        try {
            return block()
        } finally {
            validity = before
        }
    }

    /** The links so far, copied: a fixture built now does not see links added later. */
    val ok: Set<Pair<CertId, KeyId>> get() = links.toSet()

    fun key(
        keyOid: String = SymOids.KEY,
        curveOid: String? = null,
    ): SymKey = SymKey(SEED, keys++, keyOid, curveOid)

    /**
     * A leaf's key: `id-Ed25519`, which §9.2's keyability profile (K7) admits, so decision step 3 queries the leaf
     * rather than cutting it as `PRODUCER_UNKEYABLE`. It takes the next ordinal, as [key] does.
     */
    fun leafKey(): SymKey = key(SymOids.ED25519)

    /** A one-RDN name `CN=[cn]`, its value under the string [tag] (UTF8String by default). */
    fun name(
        cn: String,
        tag: Int = UTF8_STRING,
    ): ByteArray =
        TestDer.seq(TestDer.tlv(0x31, TestDer.seq(TestDer.oid("2.5.4.3"), TestDer.tlv(tag, TestDer.ascii(cn)))))

    /**
     * A certificate. [signer] is the key whose link verifies it (null: a signature no key verifies); the outer
     * `signatureAlgorithm` is the TBS one ([withOuterAlgorithm] changes it); [extensions] are [ski] and [aki] TLVs; the
     * `Validity` is [validity]'s. Each call takes a fresh serial, so two calls never give the same bytes.
     */
    fun cert(
        label: String,
        subject: ByteArray,
        issuer: ByteArray,
        key: SymKey = key(),
        signer: SymKey? = null,
        sigOid: String = SymOids.SIGNATURE,
        extensions: List<ByteArray> = emptyList(),
    ): FixtureCert {
        val serial = ++serials
        val t =
            TestCert(
                serial = TestDer.tlv(0x02, TestDer.bytes(0x01, serial shr 8 and 0xff, serial and 0xff)),
                tbsSignature = TestDer.seq(TestDer.oid(sigOid)),
                issuer = issuer,
                validity = validity,
                subject = subject,
                spki = key.spki,
                extensions = extensions,
                outerAlgorithm = TestDer.seq(TestDer.oid(sigOid)),
                signature = TestDer.tlv(0x03, TestDer.bytes(0x00, serial and 0xff)),
            )
        val c = FixtureCert(label, t.der, t.tbs, subject, key)
        labels[c.bytesHash] = label
        signer?.let { verifies(c, it) }
        return c
    }

    /** [c] with the outer `signatureAlgorithm` TLV [outer]: the same TBS, so the same links. */
    fun withOuterAlgorithm(
        c: FixtureCert,
        outer: ByteArray,
    ): FixtureCert {
        val der = TestDer.seq(c.tbs, outer, TestDer.tlv(0x03, TestDer.bytes(0x00, 0x01)))
        return FixtureCert(c.label, der, c.tbs, c.subject, c.key).also { labels[it.bytesHash] = c.label }
    }

    /** A self-signed root named [cn]. */
    fun root(
        label: String,
        cn: String,
        key: SymKey = key(),
        sigOid: String = SymOids.SIGNATURE,
    ): FixtureCert = name(cn).let { cert(label, it, it, key, signer = key, sigOid = sigOid) }

    /** [key] verifies [child]'s signature. */
    fun verifies(
        child: FixtureCert,
        key: SymKey,
    ) {
        links += CertId.of(child.tbs) to key.id
    }

    /** The fixture label of [bytesHash], or a short hash for a certificate this world did not issue. */
    fun label(bytesHash: ByteString): String = labels[bytesHash] ?: bytesHash.hex().take(8)

    companion object {
        const val SEED: Long = 0x5eed_0121
        const val UTF8_STRING: Int = 0x0c
        const val PRINTABLE_STRING: Int = 0x13
        const val TELETEX_STRING: Int = 0x14

        /** An SKI extension of [key]: its key identifier. */
        fun ski(key: SymKey): ByteArray =
            TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, TestDer.tlv(0x04, key.keyIdentifier))

        /** An AKI extension with [value], the extension's `AuthorityKeyIdentifier` SEQUENCE. */
        fun aki(value: ByteArray): ByteArray = TestDer.extension(Oid.AUTHORITY_KEY_IDENTIFIER, value)

        /** An AKI extension value with only the issuer-and-serial form: `[1] GeneralNames`, `[2] serial`. */
        fun akiIssuerAndSerial(issuer: ByteArray): ByteArray =
            TestDer.seq(TestDer.tlv(0xa1, TestDer.tlv(0xa4, issuer)), TestDer.tlv(0x82, TestDer.bytes(1)))
    }
}
