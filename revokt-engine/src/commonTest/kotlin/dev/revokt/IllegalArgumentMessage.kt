// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.assertFailsWith

/** The message of the [IllegalArgumentException] [block] throws; fails the test when it throws none. */
internal fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!
