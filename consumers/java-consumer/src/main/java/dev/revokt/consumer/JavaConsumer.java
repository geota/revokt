// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
package dev.revokt.consumer;

import dev.revokt.RevoktLifecycle;
import dev.revokt.RevoktLimits;

/** A Java caller sees the limits as static fields and the lifecycle as a plain enum (spec §4 public type rule). */
public final class JavaConsumer {
    private JavaConsumer() {}

    public static void main(String[] args) {
        if (RevoktLimits.MAX_DEPTH != 16) {
            throw new IllegalStateException("MAX_DEPTH is not readable from Java as a static field");
        }
        if (RevoktLifecycle.valueOf("STARTED") != RevoktLifecycle.STARTED) {
            throw new IllegalStateException("RevoktLifecycle is not a plain enum from Java");
        }
        System.out.println("java-consumer: ok");
    }
}
