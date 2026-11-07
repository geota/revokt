// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** The level of a [RevoktLogger] message (spec §3). Closed; every "logged" in the spec names its level. */
public enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
}
