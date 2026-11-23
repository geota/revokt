// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
package dev.revokt.consumer

import dev.revokt.Outcome
import dev.revokt.RevoktLimits

/** A Kotlin consumer resolves the KMP root artifact and sees the public surface without opt-ins (spec §3.1 item 4). */
fun main() {
    check(RevoktLimits.MAX_CHANGESET_RECORDS == 1_024) { "MAX_CHANGESET_RECORDS is not 1,024" }
    check(Outcome.entries.size == 2) { "Outcome is not the closed two-value enum" }
    println("kotlin-consumer: ok")
}
