// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** Which of `ENGINE_ERROR`'s producers attached a `Finding.EngineError` (spec §4, §5.1). Growable. */
public enum class EngineErrorProducer {
    /** The catch boundary around the evaluation. */
    BOUNDARY,

    /** An engine result: `CrliteQueryResult.ENGINE_ERROR`, or `NO_DATA` while a generation is published. */
    ENGINE,

    /** An exemption that threw. */
    EXEMPTION,
}
