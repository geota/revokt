// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * How serious a [PolicyDiagnostic] is (spec §4). Closed. The enforcement and policy setters and `start()` throw iff
 * `validate(enforcement)` returns an [ERROR].
 */
public enum class Severity {
    WARNING,
    ERROR,
}
