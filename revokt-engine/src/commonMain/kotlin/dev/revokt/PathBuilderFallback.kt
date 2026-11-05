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
     * DERs, leaf first, with the trust anchor's certificate appended last; null when no path is found.
     */
    public fun build(
        chainDer: List<ByteArray>,
        anchors: AnchorSnapshot,
        nowMillis: Long,
    ): List<ByteArray>?
}
