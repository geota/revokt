// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.RevoktStorage

/**
 * `RevoktStorage.inMemory()` (spec §3): a map from key to a private copy of the bytes, behind a reader-writer lock, so a
 * [read] sees a write whole or not at all. Directories exist only as key prefixes, as on a file system: a key cannot be
 * written under a key that holds a file, nor where keys sit beneath it, so code tested here meets the conflicts
 * `JvmStorage` would. There is no lock key and there are no temporary keys, so [names] lists every key.
 */
internal class InMemoryStorage : RevoktStorage {
    private val guard = ReadWriteGuard()
    private val files = HashMap<String, ByteArray>()

    override fun read(name: String): ByteArray? {
        StoreKeys.requireKey(name)
        return guard.read { files[name]?.copyOf() }
    }

    override fun write(
        name: String,
        bytes: ByteArray,
    ) {
        StoreKeys.requireKey(name)
        val copy = bytes.copyOf()
        guard.write {
            var slash = name.indexOf('/')
            while (slash >= 0) {
                require(name.substring(0, slash) !in files) { "'$name' is under '${name.substring(0, slash)}', a file" }
                slash = name.indexOf('/', slash + 1)
            }
            val below = "$name/"
            require(files.keys.none { it.startsWith(below) }) { "'$name' is a directory" }
            files[name] = copy
        }
    }

    override fun delete(name: String) {
        StoreKeys.requireKey(name)
        guard.write { files.remove(name) }
    }

    override fun names(): Set<String> = guard.read { files.keys.toSet() }

    override fun lock(): AutoCloseable = AutoCloseable { }
}
