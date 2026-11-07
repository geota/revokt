// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame

/** `RevoktLoggers.jul()` (spec §3, #105) over `java.util.logging`, and `safeLog`'s fatal-error rule (§5.5). */
class RevoktLoggersTest {
    private class Recording : Handler() {
        val records = mutableListOf<LogRecord>()

        override fun publish(record: LogRecord) {
            records += record
        }

        override fun flush() = Unit

        override fun close() = Unit
    }

    @Test
    fun `jul logs each level under dev revokt at its JUL level`() {
        val logger = Logger.getLogger("dev.revokt")
        val handler = Recording()
        val level = logger.level
        val useParent = logger.useParentHandlers
        logger.level = Level.ALL
        logger.useParentHandlers = false
        logger.addHandler(handler)
        try {
            val cause = IllegalStateException("cause")
            for (l in LogLevel.entries) RevoktLoggers.jul().log(l, "at $l", cause.takeIf { l == LogLevel.ERROR })
            assertEquals(
                listOf(Level.FINE, Level.INFO, Level.WARNING, Level.SEVERE),
                handler.records.map { it.level },
            )
            assertEquals(LogLevel.entries.map { "at $it" }, handler.records.map { it.message })
            assertEquals(List(4) { "dev.revokt" }, handler.records.map { it.loggerName })
            assertSame(cause, handler.records.last().thrown)
            assertNull(handler.records.first().thrown)
        } finally {
            logger.removeHandler(handler)
            logger.level = level
            logger.useParentHandlers = useParent
        }
    }

    @Test
    fun `jul is one logger`() {
        assertSame(RevoktLoggers.jul(), RevoktLoggers.jul())
    }

    @Test
    fun `safeLog swallows a StackOverflowError and rethrows a fatal error`() {
        fun throwing(t: Throwable) = RevoktLogger { _, _, _ -> throw t }
        throwing(StackOverflowError()).safeLog(LogLevel.INFO, "swallowed")
        throwing(LinkageError()).safeLog(LogLevel.INFO, "swallowed")
        assertFailsWith<OutOfMemoryError> { throwing(OutOfMemoryError()).safeLog(LogLevel.INFO, "rethrown") }
    }
}
