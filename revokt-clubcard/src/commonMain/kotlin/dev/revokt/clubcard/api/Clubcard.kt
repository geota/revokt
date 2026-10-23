// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi

/**
 * Apache-licensed glue over the MPL-2.0 port in `dev.revokt.clubcard.port` (spec §3.1 item 2). The port itself lands
 * in the 0.1 "clubcard port" issue; this file fixes the package split and the marker so the module shape exists first.
 */
@RevoktInternalApi
public object Clubcard {
    /** Word width of the ribbon filter, the `W = 4` of spec §6.2. */
    public val wordWidth: Int = 4
}
