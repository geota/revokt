// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** The status of a verdict's path finding (spec §4). Growable; M5 adds `NOT_APPLICABLE`. */
public enum class PathStatus {
    FOUND,
    NO_ISSUER,
    ISSUER_UNVERIFIED,
    PATH_BUDGET_EXCEEDED,
    PARSE_FAILED,
    NOT_WALKED,
}
