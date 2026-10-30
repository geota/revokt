// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** The only CRLite status type: what every engine's query answers (spec §3.2). Growable. */
public enum class CrliteQueryResult {
    NOT_REVOKED,
    REVOKED,
    NOT_COVERED,
    NOT_ENROLLED,
    NO_SCTS,
    NO_DATA,
    ENGINE_ERROR,
}
