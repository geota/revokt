// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import java.io.File

/** The committed fixture generation's filters (`corpus/clubcard`: the full filter and its delta, each with its own index). */
internal object FixtureIndex {
    /** Every key of each index of the fixture generation (§6.2, §6.3), read with the clubcard port, as hex. */
    @OptIn(RevoktInternalApi::class)
    val keys: Set<String> by lazy {
        val root = File(checkNotNull(System.getProperty("revokt.clubcardCorpus")) { "revokt.clubcardCorpus not set" })
        listOf("compat-full/20261017-1-compat.filter", "compat-delta/20261021-1-compat.filter.delta")
            .flatMap { ClubcardFilters.decode(File(root, it).readBytes()).index.keys }
            .map { it.hex() }
            .toSet()
    }
}
