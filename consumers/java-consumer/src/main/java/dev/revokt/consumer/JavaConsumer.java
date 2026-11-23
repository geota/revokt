// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
package dev.revokt.consumer;

import dev.revokt.Outcome;
import dev.revokt.RevoktLimits;

/** A Java caller sees the limits as static fields and the closed enums as plain enums (spec §4 public type rule). */
public final class JavaConsumer {
    private JavaConsumer() {}

    public static void main(String[] args) {
        if (RevoktLimits.MAX_FILTER_BYTES != 16L << 20) {
            throw new IllegalStateException("MAX_FILTER_BYTES is not readable from Java as a static field");
        }
        if (Outcome.valueOf("REJECT") != Outcome.REJECT) {
            throw new IllegalStateException("Outcome is not a plain enum from Java");
        }
        System.out.println("java-consumer: ok");
    }
}
