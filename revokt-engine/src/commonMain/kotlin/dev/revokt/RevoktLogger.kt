// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.walker.isFatal

/**
 * Where revokt logs (spec §3). On the JVM, `RevoktLoggers.jul()` logs through `java.util.logging`. A logger that throws
 * is swallowed by revokt, so a broken logger never changes a verdict.
 */
public fun interface RevoktLogger {
    public fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    )
}

/**
 * [RevoktLogger.log] as every revokt caller makes it (spec §3): a throwing logger is swallowed. A fatal error (§5.5) is
 * rethrown, as at every catch of consumer code.
 */
@Suppress("TooGenericExceptionCaught") // §3: a throwing logger is swallowed; §5.5: every throwable but a fatal error
internal fun RevoktLogger.safeLog(
    level: LogLevel,
    message: String,
    cause: Throwable? = null,
) {
    try {
        log(level, message, cause)
    } catch (t: Throwable) {
        if (isFatal(t)) throw t
    }
}
