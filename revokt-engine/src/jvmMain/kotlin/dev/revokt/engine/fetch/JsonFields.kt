// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.json.JsonValue

/** [value]'s string, or null when it is absent or not a JSON string. */
internal fun stringOf(value: JsonValue?): String? = (value as? JsonString)?.value

/** An integer literal from 0 to `Long.MAX_VALUE`; a double such as `1.0` is not one. */
internal fun countOf(value: JsonValue?): Long? = (value as? JsonInteger)?.takeIf { !it.negative }?.toLongOrNull()
