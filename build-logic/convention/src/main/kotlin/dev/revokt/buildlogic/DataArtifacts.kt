// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

/**
 * The data artifacts' facts (spec §3, §6.5, §7.2; CONTRIBUTING §3 "Licensing"), in one place: the coordinates that
 * `data-artifact` publishes and the only ones `verifyPomLicenses` accepts the data licence for.
 *
 * [GROUP] is a placeholder: whether the data artifacts stay in `dev.revokt` or move to a namespace owned by the
 * data-only Portal account (CONTRIBUTING §9) is the maintainer's open decision on #145; only publishing (#149) depends on
 * it, and changing it here moves the plugin and the licence check together.
 */
object DataArtifacts {
    const val GROUP = "dev.revokt"

    /** The CRLite channels' wire names (`CrliteChannel.wireName`), one seed artifact each. */
    val CHANNELS: List<String> = listOf("compat", "default")

    /** Spec §3: the data artifacts' licence text, exactly. */
    const val LICENSE = "No copyright claimed; contains Mozilla Remote Settings data"

    /** The project whose internals the seed job's entry calls (`friendPaths`, #145). */
    const val ENGINE_PROJECT = ":revokt-engine"

    /** The Gradle property that carries the date version, `YYYY.MM.DD` (spec §7.2). */
    const val VERSION_PROPERTY = "revokt.seedVersion"

    fun artifactId(channel: String): String = "revokt-seed-$channel"

    /** The closed set of data artifact ids: no glob, so another `revokt-seed-*` name is a code artifact. */
    val ARTIFACT_IDS: Set<String> = CHANNELS.map(::artifactId).toSet()

    /** `SeedSource.bundled()`'s resource for [channel], relative to the class-path root. */
    fun resource(channel: String): String = "revokt/seed-$channel.zip"

    /** Whether `group:artifact` is a data artifact's coordinates, compared exactly. */
    fun isData(
        group: String,
        artifact: String,
    ): Boolean = group == GROUP && artifact in ARTIFACT_IDS
}
