// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.Extension
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString.Companion.toByteString
import java.math.BigInteger
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * The §9.2 Java field normalisation, applied to any platform oracle's `X509Certificate` against revokt's parse. A
 * platform getter that throws on an accepted certificate marks its field `unavailable`.
 */
internal object JavaFields {
    /** One normalised field comparison: [mismatch] is null when the field agrees, [unavailable] when its getter threw. */
    class Field(
        val name: String,
        val mismatch: String?,
        val unavailable: Boolean = false,
    )

    /**
     * The §9.2 normalised fields of [x509] against revokt's [c]: the serial by value, the SPKI by SHA-256, the names in
     * `CANONICAL` form, every extension value unwrapped, the critical OIDs and the validity in epoch milliseconds.
     * revokt's side is computed outside the getter's guard, so only a platform getter can make a field `unavailable`.
     */
    fun compare(
        x509: X509Certificate,
        c: ParsedCertificate,
    ): List<Field> {
        val extensions = c.tbs.extensions
        return listOf(
            field("serial", c.rawSerial().takeIf { it.isNotEmpty() }?.let(::BigInteger)) { x509.serialNumber },
            field("spki", sha(c.rawSpki())) { sha(x509.publicKey.encoded) },
            field("issuer", canonical(X500Principal(c.rawIssuer()))) { canonical(x509.issuerX500Principal) },
            field("subject", canonical(X500Principal(c.rawSubject()))) { canonical(x509.subjectX500Principal) },
            // `getExtensionValue` answers one value per OID, the first where a platform accepts duplicates (Conscrypt).
            field(
                "extensions",
                extensions.reversed().associate { name(it) to Oracle3a.hex(it.value.bytes(c.tbsBytes)) },
            ) {
                (x509.criticalExtensionOIDs.orEmpty() + x509.nonCriticalExtensionOIDs.orEmpty()).associateWith {
                    unwrap(x509.getExtensionValue(it))
                }
            },
            field("critical", extensions.filter { it.critical }.map(::name).toSet()) {
                x509.criticalExtensionOIDs.orEmpty()
            },
            field("notBefore", c.tbs.validity.notBeforeMillis) { x509.notBefore.time },
            field("notAfter", c.tbs.validity.notAfterMillis) { x509.notAfter.time },
        )
    }

    @Suppress("TooGenericExceptionCaught") // §9.2: a platform getter that throws marks its field unavailable
    private fun field(
        name: String,
        revokt: Any?,
        platform: () -> Any?,
    ): Field =
        try {
            val value = platform()
            Field(name, if (value == revokt) null else "platform $value, revokt $revokt")
        } catch (e: RuntimeException) {
            Field(name, "getter threw $e", unavailable = true)
        }

    /** The dotted OID, or a placeholder no JDK OID equals where revokt cannot name it. */
    private fun name(e: Extension): String = e.oidDotted ?: "unnamed@${e.oid.start}"

    /** `getExtensionValue`'s DER OCTET STRING, unwrapped to its content (hex). */
    private fun unwrap(wrapped: ByteArray?): String? {
        if (wrapped == null || wrapped.isEmpty() || wrapped[0] != 0x04.toByte()) return null
        val header = Oracle1.header(wrapped, 0) ?: return null
        return Oracle3a.hex(wrapped.copyOfRange(header.size, wrapped.size))
    }

    private fun canonical(p: X500Principal): String = p.getName(X500Principal.CANONICAL)

    private fun sha(b: ByteArray): String = b.toByteString().sha256().hex()
}
