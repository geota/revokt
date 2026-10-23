// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
package dev.revokt.consumer;

import dev.revokt.RevoktLimits;

/** The Maven consumer build (spec §9 "Maven consumer build"): resolves through the BOM and compiles against the jvm artifact. */
public final class MavenConsumer {
    private MavenConsumer() {}

    public static int maxCertBytes() {
        return RevoktLimits.MAX_CERT_BYTES;
    }
}
