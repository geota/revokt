// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.parse.ExtendedKeyUsage
import dev.revokt.engine.parse.ExtensionRead
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.ParsedCertificate

/**
 * The purpose an issuer's extKeyUsage must list when it has one (#237): the request's, `serverAuth` unless a binding
 * says otherwise (a client-certificate check is `clientAuth`). Internal: no public type carries it.
 */
internal enum class RequiredEku(
    oid: ByteArray,
) {
    /** `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1). */
    SERVER_AUTH(byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)),

    /** `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2). */
    CLIENT_AUTH(byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02)),
    ;

    private val oid: ByteArray = oid.copyOf()

    /** True when [eku] lists this purpose exactly; `anyExtendedKeyUsage` does not count, as in webpki and pkix. */
    fun listedIn(eku: ExtendedKeyUsage): Boolean = eku.contains(oid)
}

/**
 * What one certificate offers as an issuer, read once from its parse (#225, #237). Every unreadable value fails closed.
 *
 * - [isCa]: the one basicConstraints reads `cA = TRUE` with a `pathLenConstraint`, if any, of at most 127, pkix's
 *   bound (`OptionalInteger`). Absent, FALSE, malformed, duplicated or a larger `pathLen` is false (webpki
 *   `EndEntityUsedAsCa`, `verify_cert.rs` 448; pkix `ERROR_CA_CERT_INVALID`, `pkixcheck.cpp` 712–715).
 * - [pathLen]: the `pathLenConstraint`, null when absent.
 * - [keyCertSign]: no keyUsage, or one that sets `keyCertSign`. A malformed keyUsage, or one with no bits, is false
 *   (pkix `CheckKeyUsage`, `pkixcheck.cpp` 405 ff.; webpki ignores keyUsage, `verify_cert.rs` 370–375, so this is
 *   stricter than webpki, as Firefox and the JDK's `KeyChecker` are).
 * - [allows]: no extKeyUsage, or one that lists the purpose. An empty or malformed one is false (webpki
 *   `check_eku` and `ExtendedKeyUsage::validate`, `verify_cert.rs` 386–397 and 572–598; pkix
 *   `CheckExtendedKeyUsage`, `pkixcheck.cpp` 816–846).
 */
internal class IssuerProfile private constructor(
    val isCa: Boolean,
    val pathLen: Int?,
    val keyCertSign: Boolean,
    private val eku: ExtensionRead<ExtendedKeyUsage>,
) {
    fun allows(purpose: RequiredEku): Boolean =
        when (eku) {
            is ExtensionRead.Absent -> true
            is ExtensionRead.Value -> purpose.listedIn(eku.value)
            is ExtensionRead.Failed -> false
        }

    /**
     * True when this certificate may issue for [purpose] with [casBelow] CAs between it and the leaf: a CA within its
     * `pathLenConstraint` (webpki `sub_ca_count > len`, `verify_cert.rs` 449; pkix `subCACount > pathLenConstraint`,
     * `pkixcheck.cpp` 718; neither exempts a self-issued certificate), with `keyCertSign`, allowing [purpose].
     */
    fun mayIssue(
        casBelow: Int,
        purpose: RequiredEku,
    ): Boolean = isCa && (pathLen == null || casBelow <= pathLen) && keyCertSign && allows(purpose)

    internal companion object {
        /** pkix reads `pathLenConstraint` as a byte, 0 to 127 (`der::OptionalInteger`). */
        private const val MAX_PATH_LEN = 127

        fun of(p: ParsedCertificate): IssuerProfile {
            val bc = (ExtensionValues.basicConstraints(p) as? ExtensionRead.Value)?.value
            val ca = bc?.ca == true && (bc.pathLen ?: 0) <= MAX_PATH_LEN
            val keyCertSign =
                when (val ku = ExtensionValues.keyUsage(p)) {
                    is ExtensionRead.Absent -> true

                    // No bits at all (pkix: "Reject empty bit masks") has no keyCertSign either.
                    is ExtensionRead.Value -> ku.value.keyCertSign

                    is ExtensionRead.Failed -> false
                }
            return IssuerProfile(ca, bc?.pathLen, keyCertSign, ExtensionValues.extendedKeyUsage(p))
        }
    }
}
