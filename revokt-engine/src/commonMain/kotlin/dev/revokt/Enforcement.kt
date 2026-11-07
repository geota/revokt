// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * How a verdict is applied (spec §4). Closed. `Rejected` means "policy says reject"; only the trust manager decides
 * whether to throw.
 */
public enum class Enforcement {
    /** A rejected verdict fails the handshake. */
    ENFORCE,

    /** Every step runs and is reported, and no verdict fails the handshake. */
    OBSERVE,

    /** Platform only: steps 2 to 4 do not run, no events are emitted, and `unevaluated[OFF]` advances. */
    OFF,
}
