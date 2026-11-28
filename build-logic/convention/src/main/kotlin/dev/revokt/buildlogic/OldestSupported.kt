// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.TaskAction

/**
 * The oldest supported engine minor the weekly seed job smoke-loads each seed with (spec §7.2; CONTRIBUTING §9).
 *
 * One place names it: [PROPERTY] in `gradle.properties`, the `X.Y.Z` of that minor's release on Maven Central, empty
 * until a minor is released. The PR after each release sets it, with the lockfile and verification entries the
 * release's artifacts need (STRICT locking and dependency verification name the exact version either way, so a
 * version derived from tags alone would still need that commit). The job passes the newest `vX.Y.Z` tag as
 * [NEWEST_RELEASE_PROPERTY], and [problem] holds the two together, so a release that the property does not name fails
 * the job instead of falling back to the run's own commit.
 */
internal object OldestSupported {
    /** `gradle.properties`: the release of the oldest supported minor, `X.Y.Z`; empty while none is released. */
    const val PROPERTY = "revokt.oldestSupportedVersion"

    /** Passed by the weekly job: the newest `vX.Y.Z` tag's `X.Y.Z`, empty when there is none. */
    const val NEWEST_RELEASE_PROPERTY = "revokt.newestRelease"

    /** The released module the smoke load compiles and runs on (its POM brings revokt-engine, an `api` dependency). */
    const val MODULE = "${Conventions.GROUP}:revokt-jsse"

    private val VERSION = Regex("""(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})""")

    /** `[major, minor, patch]` of a plain `X.Y.Z` (no `v`, no pre-release, no leading zero); null otherwise. */
    fun parse(version: String): List<Int>? = VERSION.matchEntire(version)?.groupValues?.drop(1)?.map { it.toInt() }

    /**
     * Why the job must fail, or null when [oldest] (the property; blank when unset) is consistent with [newest] (the
     * newest release tag's version; blank when there is none, null when the job did not pass it). Both blank is the
     * fallback: nothing is released, so the oldest supported minor is the run's own commit's.
     */
    fun problem(
        oldest: String,
        newest: String?,
    ): String? {
        if (newest == null) {
            return "the oldest-minor smoke load needs -P$NEWEST_RELEASE_PROPERTY=<the newest vX.Y.Z tag without the v>, " +
                "empty when no release exists (release-seed.yml passes it)."
        }
        val released = newest.trim()
        val named = oldest.trim()
        val newestParts =
            if (released.isEmpty()) {
                null
            } else {
                parse(released) ?: return "-P$NEWEST_RELEASE_PROPERTY='$released' is not an X.Y.Z version."
            }
        if (named.isEmpty()) {
            return newestParts?.let {
                "v$released is released, but $PROPERTY in gradle.properties is empty: set it to the release of the oldest " +
                    "supported minor, with its lockfile and verification entries (CONTRIBUTING §9, docs/dev/deps.md), " +
                    "rather than smoke-load with this commit."
            }
        }
        val oldestParts = parse(named) ?: return "$PROPERTY='$named' is not an X.Y.Z version."
        return when {
            newestParts == null ->
                "$PROPERTY names $named, but no vX.Y.Z tag exists: it must name a released version."
            compare(oldestParts, newestParts) > 0 ->
                "$PROPERTY names $named, newer than the newest release v$released."
            newestParts[0] == 0 && oldestParts.take(2) != newestParts.take(2) ->
                "$PROPERTY names $named, but only the latest 0.x minor is supported (CONTRIBUTING §9): set it to a " +
                    "release of ${newestParts[0]}.${newestParts[1]}, with its lockfile and verification entries."
            else -> null
        }
    }

    private fun compare(
        a: List<Int>,
        b: List<Int>,
    ): Int = a.zip(b).map { (x, y) -> x.compareTo(y) }.firstOrNull { it != 0 } ?: 0
}

/**
 * `checkOldestSupportedVersion` ([OldestSupported.problem]): fails unless `revokt.oldestSupportedVersion` and the
 * newest release tag agree. Every oldest-minor smoke load and its compilation depend on it, so a mismatch fails before
 * anything resolves the released artifact. It declares no outputs, so it is never up to date.
 */
abstract class CheckOldestSupportedTask : DefaultTask() {
    /** `revokt.oldestSupportedVersion`, blank when unset. */
    @get:Input
    abstract val oldest: Property<String>

    /** `-Prevokt.newestRelease`; absent when not passed, which fails. */
    @get:Input
    @get:Optional
    abstract val newest: Property<String>

    @TaskAction
    fun check() {
        val named = oldest.get().trim()
        OldestSupported.problem(named, newest.orNull)?.let { throw GradleException(it) }
        if (named.isEmpty()) {
            logger.lifecycle("No engine minor is released yet: the oldest supported one is this commit's, smoke-loaded by smokeLoadSeed<Channel>.")
        } else {
            logger.lifecycle("The oldest supported engine minor's release: ${OldestSupported.MODULE}:$named (newest release v${newest.get().trim()}).")
        }
    }
}
