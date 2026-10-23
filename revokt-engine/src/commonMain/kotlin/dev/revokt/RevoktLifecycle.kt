// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * `CREATED → STARTED → CLOSED` (spec §5.1). Closed enum, commonMain: `RevoktState` is an engine output type while
 * `Revokt` lives in revokt-jsse; named to avoid `androidx.lifecycle.Lifecycle`.
 */
public enum class RevoktLifecycle {
    CREATED,
    STARTED,
    CLOSED,
}
