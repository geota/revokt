// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.util.logging.Level
import java.util.logging.Logger

/** The JVM's [RevoktLogger]s (spec §3). */
public object RevoktLoggers {
    // A strong reference: java.util.logging holds its named loggers weakly, so a level set on "dev.revokt" through
    // this logger would otherwise be lost when it is collected.
    private val julLogger: Logger = Logger.getLogger("dev.revokt")

    private val jul = RevoktLogger { level, message, cause -> julLogger.log(level.julLevel(), message, cause) }

    /**
     * A logger over the `java.util.logging` logger `"dev.revokt"`: [LogLevel.DEBUG] logs at `FINE`, [LogLevel.INFO] at
     * `INFO`, [LogLevel.WARN] at `WARNING` and [LogLevel.ERROR] at `SEVERE`.
     */
    @JvmStatic
    public fun jul(): RevoktLogger = jul
}

internal fun LogLevel.julLevel(): Level =
    when (this) {
        LogLevel.DEBUG -> Level.FINE
        LogLevel.INFO -> Level.INFO
        LogLevel.WARN -> Level.WARNING
        LogLevel.ERROR -> Level.SEVERE
    }
