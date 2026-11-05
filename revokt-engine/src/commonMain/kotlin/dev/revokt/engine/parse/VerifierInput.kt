// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/**
 * An `AlgorithmIdentifier` as a signature verifier reads it (spec §3 "Verifier contract"): the dotted [oid], the
 * [parameters] TLV (null when absent) and [parametersOid], the parameters' OID when they are one (the named curve of
 * `id-ecPublicKey`, as `Cert.curveOid` reads it).
 */
internal class AlgorithmId(
    val oid: String,
    val parameters: ByteArray?,
    val parametersOid: String?,
) {
    /** True when the parameters are absent or an ASN.1 NULL, the two spellings of "no parameters" (spec §5.1). */
    val noParameters: Boolean get() = parameters == null || parameters.contentEquals(NULL)

    private companion object {
        val NULL = byteArrayOf(0x05, 0x00)
    }
}

/**
 * The verifier's readers over bytes it did not produce (spec §9.1 target "`AlgorithmIdentifier`/PSS parameters"): the
 * signed TBS `AlgorithmIdentifier`, the candidate's `SubjectPublicKeyInfo` and the `RSASSA-PSS-params`. Each reads its
 * whole input with the parser's [DerReader] and answers null for anything that is not exactly that shape; none throws.
 */
internal object VerifierInput {
    private const val SEQUENCE = 0x30
    private const val OBJECT_IDENTIFIER = 0x06
    private const val BIT_STRING = 0x03
    private const val INTEGER = 0x02
    private const val CONTEXT_CONSTRUCTED = 0xa0
    private const val PSS_FIELDS = 4

    /** `sha1`, the default hash of `RSASSA-PSS-params` and of its MGF1 (RFC 4055 §3.1). */
    const val SHA1: String = "1.3.14.3.2.26"

    /** `id-mgf1` (RFC 8017 B.2.1). */
    const val MGF1: String = "1.2.840.113549.1.1.8"

    private const val DEFAULT_SALT_LENGTH = 20

    /** The `AlgorithmIdentifier` TLV [der]: a SEQUENCE of an OID and at most one parameters element, nothing after. */
    fun algorithm(der: ByteArray): AlgorithmId? =
        read(der) { r ->
            algorithm(der, r).also { r.requireEnd("AlgorithmIdentifier") }
        }

    /** The algorithm of the `SubjectPublicKeyInfo` TLV [der]: a SEQUENCE of an `AlgorithmIdentifier` and a BIT STRING. */
    fun spkiAlgorithm(der: ByteArray): AlgorithmId? =
        read(der) { r ->
            val fields = r.child(r.read(SEQUENCE, HeaderSite.SPKI))
            r.requireEnd("SubjectPublicKeyInfo")
            val algorithm = algorithm(der, fields)
            fields.read(BIT_STRING, HeaderSite.SPKI)
            fields.requireEnd("SubjectPublicKeyInfo")
            algorithm
        }

    /**
     * `RSASSA-PSS-params` (RFC 4055 §3.1) from the [parameters] TLV of an `id-RSASSA-PSS` signature
     * `AlgorithmIdentifier`: null when absent (they MUST be present there) or malformed. The four fields are optional,
     * explicitly tagged `[0]` to `[3]` in that order, each at most once; an absent field takes its DEFAULT (SHA-1,
     * MGF1 with SHA-1, 20, 1), and a DEFAULT written out is accepted. A hash `AlgorithmIdentifier` has absent or NULL
     * parameters; the mask generation function is MGF1, the only one RFC 4055 defines, and names its hash; the salt
     * length and trailer field are minimal, non-negative INTEGERs that fit an `Int`.
     */
    fun pss(parameters: ByteArray?): PssParameters? {
        if (parameters == null) return null
        return read(parameters) { r ->
            val fields = r.child(r.read(SEQUENCE, HeaderSite.TBS_SIGNATURE))
            r.requireEnd("RSASSA-PSS-params")
            var hash = SHA1
            var mgfHash = SHA1
            var salt = DEFAULT_SALT_LENGTH
            var trailer = 1
            var next = 0
            while (fields.hasMore()) {
                val index = fields.peekTag() - CONTEXT_CONSTRUCTED
                if (index !in
                    next until PSS_FIELDS
                ) {
                    fail("RSASSA-PSS-params field tag ${fields.peekTag()} out of order")
                }
                next = index + 1
                val field = fields.child(fields.readAny(HeaderSite.TBS_SIGNATURE))
                when (index) {
                    0 -> hash = hashAlgorithm(parameters, field) ?: return@read null
                    1 -> mgfHash = maskGenHash(parameters, field) ?: return@read null
                    2 -> salt = integer(parameters, field) ?: return@read null
                    else -> trailer = integer(parameters, field) ?: return@read null
                }
                field.requireEnd("RSASSA-PSS-params field")
            }
            PssParameters(hash, mgfHash, salt, trailer)
        }
    }

    private fun algorithm(
        der: ByteArray,
        r: DerReader,
    ): AlgorithmId? {
        val fields = r.child(r.read(SEQUENCE, HeaderSite.TBS_SIGNATURE))
        val oid = minimalOid(der, fields.read(OBJECT_IDENTIFIER, HeaderSite.TBS_SIGNATURE).content) ?: return null
        val parameters = if (fields.hasMore()) fields.readAny(HeaderSite.TBS_SIGNATURE) else null
        fields.requireEnd("AlgorithmIdentifier")
        val parametersOid =
            if (parameters?.tag == OBJECT_IDENTIFIER) minimalOid(der, parameters.content) ?: return null else null
        return AlgorithmId(oid, parameters?.let { it.tlv.bytes(der) }, parametersOid)
    }

    /**
     * The dotted OID at [content], or null when it does not decode or an arc has a leading `0x80` octet. Stricter than
     * the certificate parser's lenient [Oid.dotted] (spec §9.2): the JDK's `ObjectIdentifier` rejects a padded arc, so
     * a padded `sha256WithRSAEncryption` must not verify here as the real one, and the PSS reader stays no more lenient
     * than the JDK's decoder (the §9.1 target's differential).
     */
    private fun minimalOid(
        der: ByteArray,
        content: Span,
    ): String? {
        var arcStart = true
        for (i in content.start until content.end) {
            val b = der[i].toInt() and 0xff
            if (arcStart && b == 0x80) return null
            arcStart = b and 0x80 == 0
        }
        return Oid.dotted(der, content)
    }

    /** A `HashAlgorithm`: an `AlgorithmIdentifier` with absent or NULL parameters; its OID. */
    private fun hashAlgorithm(
        der: ByteArray,
        r: DerReader,
    ): String? = algorithm(der, r)?.takeIf { it.noParameters }?.oid

    /** A `MaskGenAlgorithm`: `id-mgf1` whose parameters are a `HashAlgorithm`; the hash's OID. */
    private fun maskGenHash(
        der: ByteArray,
        r: DerReader,
    ): String? {
        val mgf = algorithm(der, r) ?: return null
        if (mgf.oid != MGF1) return null
        val hash = mgf.parameters ?: return null
        return read(hash) { hashAlgorithm(hash, it) }
    }

    private fun integer(
        der: ByteArray,
        r: DerReader,
    ): Int? {
        val content = r.read(INTEGER, HeaderSite.TBS_SIGNATURE).content
        if (!Keyability.minimalInteger(der, content) || der[content.start] < 0) return null
        if (content.length > Int.SIZE_BYTES) return null
        var value = 0
        for (i in content.start until content.end) value = (value shl Byte.SIZE_BITS) or (der[i].toInt() and 0xff)
        return value
    }

    private fun <T> read(
        der: ByteArray,
        block: (DerReader) -> T?,
    ): T? =
        try {
            block(DerReader(der, 0, der.size, ParseContext()))
        } catch (_: DerException) {
            null
        }
}

/** `RSASSA-PSS-params` as read by [VerifierInput.pss]: hash and MGF1 hash OIDs, salt length and trailer field. */
internal data class PssParameters(
    val hashOid: String,
    val mgfHashOid: String,
    val saltLength: Int,
    val trailerField: Int,
)
