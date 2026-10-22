// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
package dev.revokt.consumer

import dev.revokt.RevoktLifecycle
import dev.revokt.RevoktLimits

/** A Kotlin consumer resolves the KMP root artifact and sees the public surface without opt-ins (spec §3.1 item 4). */
fun main() {
    check(RevoktLimits.MAX_PRESENTED == 64) { "MAX_PRESENTED is not 64" }
    check(RevoktLifecycle.entries.size == 3) { "RevoktLifecycle is not the closed three-state enum" }
    println("kotlin-consumer: ok")
}
