// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

// The linuxX64 purity gate only compiles (spec §3); Kotlin/Native has no VirtualMachineError to rethrow.
@Suppress("UNUSED_PARAMETER") // the expect's signature; the stub reads nothing
internal actual fun isFatal(t: Throwable): Boolean = false
