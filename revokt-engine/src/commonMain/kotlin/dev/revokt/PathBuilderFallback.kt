// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The PKIX path-building seam (spec §3, §5.1 "PKIX fallback contract"): the walker's fallback when it finds no path.
 * The JVM's is `PkixPathBuilderFallback`, which re-parses the snapshot's platform anchor encodings.
 */
public interface PathBuilderFallback {
    /**
     * Builds a path for [chainDer] (the presented chain, leaf first) under [anchors] at [nowMillis]. Returns the path's
     * DERs, leaf first, with the trust anchor's certificate appended last; null when no path is found. A throw counts
     * as a failed build, `Finding.FallbackNotUsed(FAILED)`, and its outcome is cached in neither the path nor the
     * verdict cache; every `VirtualMachineError` except `StackOverflowError` is rethrown (§5.1 decision step 6).
     *
     * A returned path must meet RFC 5280's issuer rules: every certificate between the leaf and the anchor a CA
     * (`cA = TRUE`) within its `pathLenConstraint`, with `keyCertSign` when it has keyUsage, and listing the request's
     * purpose (`serverAuth` for a server) when it has extKeyUsage; and every nameConstraints on the path, the anchor's
     * included, admitting the certificates below it. Decision step 6 checks them again (#225, #237): a path that fails
     * one, does not end at a snapshot anchor by bytes, or holds a certificate that does not parse, is a failed build,
     * `FallbackNotUsed(FAILED)`. The JDK's `CertPathBuilder("PKIX")` enforces less: it exempts self-issued
     * certificates from `pathLenConstraint` and name constraints, does not apply the anchor certificate's own
     * nameConstraints, and does not read a CA's extKeyUsage; step 6's check covers all of them.
     */
    public fun build(
        chainDer: List<ByteArray>,
        anchors: AnchorSnapshot,
        nowMillis: Long,
    ): List<ByteArray>?
}
