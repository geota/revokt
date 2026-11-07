// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.jvm.JvmOverloads

/** [RevoktStorage.lock] found the store held by another instance after its bounded wait (spec §3). */
public class StoreLockedException
    @JvmOverloads
    constructor(
        message: String,
        cause: Throwable? = null,
    ) : RuntimeException(message, cause)
