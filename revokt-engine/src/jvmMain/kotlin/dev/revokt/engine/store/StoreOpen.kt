// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.LogLevel
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLogger
import dev.revokt.RevoktStorage
import dev.revokt.WarningCode
import dev.revokt.safeLog
import java.util.concurrent.atomic.AtomicBoolean

/** What a store whose `store.version` is higher than this engine's gets (spec §3, §6.5); growable. */
internal enum class NewerLayout {
    /** Left untouched, the lock released: the instance runs in memory for the life of the process (`JvmStorage`'s). */
    IN_MEMORY,

    /** Rebuilt as a lower version is: one package owns its directory, so a higher version is a rollback (Android's). */
    REBUILD,
}

/**
 * The per-process single-instance registry (spec §5.1): one entry per store a `Revokt` in this process has opened, keyed
 * on [RevoktStorage.identity], so that a second instance on one store throws instead of sharing it: two instances on
 * one root would let one's open sweep delete the other's temp files in flight.
 */
internal object StoreRegistry {
    private val held = HashSet<Any>()

    /** Registers [key], or throws [IllegalStateException] when an instance holds it; the result deregisters it once. */
    fun register(key: Any): AutoCloseable {
        synchronized(held) {
            check(held.add(key)) {
                "another Revokt in this process holds this store: give each instance its own directory (spec §3, §5.1)"
            }
        }
        val done = AtomicBoolean(false)
        return AutoCloseable { if (done.compareAndSet(false, true)) synchronized(held) { held.remove(key) } }
    }
}

/**
 * The store `start()` runs on (spec §5.1, §6.5): the configured one, locked and registered, or a fresh in-memory store
 * for the life of the process ([fallback]) with [warning] logged. [close] releases the lock, then deregisters the
 * identity, once; a fallback holds neither.
 */
internal class OpenedStore(
    val storage: RevoktStorage,
    val warning: WarningCode?,
    val fallback: Boolean,
    private val lock: AutoCloseable?,
    private val registration: AutoCloseable?,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        try {
            lock?.close()
        } finally {
            registration?.close()
        }
    }
}

/**
 * `start()`'s store step (spec §5.1, §6.5): register the identity, take the lock, then read `store.version`.
 *
 * - A second instance on one store in this process throws [IllegalStateException] before anything else is done.
 * - `lock()` failing with [StoreLockedException] is `STORE_LOCKED`; any other failure, of [RevoktStorage.identity] or
 *   `lock()`, is `STORE_UNREADABLE`.
 * - `store.version` absent in an empty store ([RevoktStorage.isEmpty]): [StoreVersion.CURRENT] is written, silently.
 *   Absent beside other entries, malformed, or a read that throws: `STORE_UNREADABLE`, the store untouched (fail
 *   closed: a directory without `store.version` is not a revokt store, and the caller's directory is the root).
 * - Equal: the store as it is. Lower: `STORE_MIGRATED`, rebuilt ([rebuild]: every other key deleted, then the
 *   version written). Higher: `STORE_NEWER_LAYOUT`, then per the storage's [NewerLayout], run in memory with the store
 *   untouched, or rebuilt.
 *
 * Each fallback releases the lock and deregisters the identity before it returns, so does any throw, and the instance
 * then runs on a fresh in-memory store. [current] is this engine's version, a test seam.
 */
internal object StoreOpen {
    // Any failure to open is a fallback (fail closed), one return each.
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    fun open(
        storage: RevoktStorage,
        logger: RevoktLogger,
        current: Int = StoreVersion.CURRENT,
    ): OpenedStore {
        val key =
            try {
                storage.identity()
            } catch (e: Exception) {
                return fallback(logger, WarningCode.STORE_UNREADABLE, "the store could not be opened", e)
            }
        val registration = key?.let(StoreRegistry::register)
        var lock: AutoCloseable? = null
        var opened: OpenedStore? = null
        try {
            lock =
                try {
                    storage.lock()
                } catch (e: StoreLockedException) {
                    return fallback(logger, WarningCode.STORE_LOCKED, "another process holds the store's lock", e)
                } catch (e: Exception) {
                    return fallback(logger, WarningCode.STORE_UNREADABLE, "the store could not be opened", e)
                }
            val step = version(storage, current, newerLayout(storage))
            if (step is Step.Fallback) return fallback(logger, step.code, step.message, step.cause)
            val warning = (step as Step.Open).warning
            if (warning != null) logger.safeLog(LogLevel.WARN, "$warning: ${step.message}")
            return OpenedStore(storage, warning, fallback = false, lock = lock, registration = registration)
                .also { opened = it }
        } finally {
            if (opened == null) release(logger, lock, registration)
        }
    }

    /** How the `store.version` step ended. */
    private sealed class Step {
        class Open(
            val warning: WarningCode?,
            val message: String,
        ) : Step()

        class Fallback(
            val code: WarningCode,
            val message: String,
            val cause: Throwable? = null,
        ) : Step()
    }

    @Suppress("TooGenericExceptionCaught", "ReturnCount") // A store read or write that throws is STORE_UNREADABLE.
    private fun version(
        storage: RevoktStorage,
        current: Int,
        onNewer: NewerLayout,
    ): Step {
        val bytes =
            try {
                storage.read(StoreVersion.KEY)
            } catch (e: Exception) {
                return Step.Fallback(WarningCode.STORE_UNREADABLE, "store.version could not be read", e)
            }
        if (bytes == null) {
            return try {
                if (storage.isEmpty()) {
                    storage.write(StoreVersion.KEY, StoreVersion.encode(current))
                    Step.Open(null, "initialised")
                } else {
                    Step.Fallback(WarningCode.STORE_UNREADABLE, "a directory with entries and no store.version")
                }
            } catch (e: Exception) {
                Step.Fallback(WarningCode.STORE_UNREADABLE, "the empty store could not be initialised", e)
            }
        }
        val found =
            StoreVersion.parse(bytes)
                ?: return Step.Fallback(WarningCode.STORE_UNREADABLE, "store.version is malformed")
        return when {
            found == current -> {
                Step.Open(null, "current")
            }

            found < current -> {
                rebuild(storage, current, WarningCode.STORE_MIGRATED, found)
            }

            onNewer == NewerLayout.REBUILD -> {
                rebuild(storage, current, WarningCode.STORE_NEWER_LAYOUT, found)
            }

            else -> {
                Step.Fallback(
                    WarningCode.STORE_NEWER_LAYOUT,
                    "store.version $found is newer than this engine's $current",
                )
            }
        }
    }

    /**
     * The rebuild (spec §6.5): every key [RevoktStorage.names] lists but `store.version` deleted, then `store.version`
     * written, and the start task then runs as on an empty store. A rebuild that fails or is interrupted keeps the old
     * version, so the next start runs the same arm and finishes it, and no old-layout `current` or `updater.json` ever
     * sits under the new version. A delete or write that throws is `STORE_UNREADABLE`: the instance runs in memory.
     */
    @Suppress("TooGenericExceptionCaught") // A store write or delete that throws is STORE_UNREADABLE.
    private fun rebuild(
        storage: RevoktStorage,
        current: Int,
        code: WarningCode,
        found: Int,
    ): Step =
        try {
            for (name in storage.names()) if (name != StoreVersion.KEY) storage.delete(name)
            storage.write(StoreVersion.KEY, StoreVersion.encode(current))
            Step.Open(code, "store.version $found, this engine's $current: the store was rebuilt")
        } catch (e: Exception) {
            Step.Fallback(WarningCode.STORE_UNREADABLE, "the rebuild from store.version $found failed", e)
        }

    /** The storage's [NewerLayout]: `JvmStorage`'s own; `inMemory()` starts empty, so it never meets a higher version. */
    private fun newerLayout(storage: RevoktStorage): NewerLayout =
        (storage as? JvmStorage)?.onNewerLayout ?: NewerLayout.IN_MEMORY

    /** Logs [code] with [message] and returns the in-memory fallback, which holds no lock and no registration. */
    private fun fallback(
        logger: RevoktLogger,
        code: WarningCode,
        message: String,
        cause: Throwable?,
    ): OpenedStore {
        logger.safeLog(LogLevel.WARN, "$code: $message; the instance runs in memory for the life of the process", cause)
        return OpenedStore(InMemoryStorage(), code, fallback = true, lock = null, registration = null)
    }

    /** Releases [lock], then deregisters; a release that throws is logged, as the lock is dropped with its channel. */
    @Suppress("TooGenericExceptionCaught") // The fallback stands whatever the release throws.
    private fun release(
        logger: RevoktLogger,
        lock: AutoCloseable?,
        registration: AutoCloseable?,
    ) {
        try {
            lock?.close()
        } catch (e: Exception) {
            logger.safeLog(LogLevel.WARN, "releasing the store's lock threw", e)
        } finally {
            registration?.close()
        }
    }
}
