// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi

/**
 * The one declared failure of [ClubcardFilters.decode]: the bytes are not a filter revokt accepts (spec §6.3). Decode
 * only; the engine turns it into `SyncOutcome.FAILED`, never into a verdict. Any other exception out of the decoder
 * is a bug (spec §9.1 "Findings").
 */
@RevoktInternalApi
public class ClubcardFormatException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
