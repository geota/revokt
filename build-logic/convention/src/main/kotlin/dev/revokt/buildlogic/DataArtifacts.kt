// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

/**
 * The data artifacts' facts (spec §3, §6.5, §7.2; #145), in one place: the files and jars `data-artifact` writes. In 0.2
 * a seed is a GitHub release asset with attestations (#149 attaches it), not a Maven artifact: an app bundles the jar
 * itself, so `SeedSource.bundled()` finds its resource (the maintainer's decision, 2026-11-23). There is no POM; the
 * licence text travels in the jar.
 */
object DataArtifacts {
    /** The CRLite channels' wire names (`CrliteChannel.wireName`), one seed each. */
    val CHANNELS: List<String> = listOf("compat", "default")

    /** Spec §3: the data artifacts' licence text, exactly. */
    const val LICENSE = "No copyright claimed; contains Mozilla Remote Settings data"

    /** The jar entry that holds [LICENSE]. */
    const val LICENSE_ENTRY = "META-INF/LICENSE-DATA"

    /** The manifest attribute that holds [LICENSE]. */
    const val LICENSE_ATTRIBUTE = "Revokt-Data-License"

    /** The project whose internals the seed job's entry calls (`friendPaths`, #145). */
    const val ENGINE_PROJECT = ":revokt-engine"

    /** The Gradle property that carries the date version, `YYYY.MM.DD` (spec §7.2). */
    const val VERSION_PROPERTY = "revokt.seedVersion"

    /** The Gradle property that names the released seed jar `seedTimestamp<Channel>` re-verifies (#308). */
    const val SEED_JAR_PROPERTY = "revokt.seedJar"

    /** The Gradle property that names the file `seedTimestamp<Channel>` writes the verified `<ts>` to (#308). */
    const val SEED_TIMESTAMP_OUT_PROPERTY = "revokt.seedTimestampOut"

    /** The base name of [channel]'s archive and jar: `revokt-seed-<channel>.zip`, `revokt-seed-<channel>-<version>.jar`. */
    fun name(channel: String): String = "revokt-seed-$channel"

    /** `SeedSource.bundled()`'s resource for [channel], relative to the class-path root. */
    fun resource(channel: String): String = "revokt/seed-$channel.zip"
}
