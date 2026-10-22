// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.getByType

/** Reads the one version catalog from a convention plugin (the plugin classpath cannot use the `libs` accessor). */
internal object VersionCatalog {
    private fun catalog(project: Project) =
        runCatching { project.extensions.getByType<VersionCatalogsExtension>().named("libs") }.getOrNull()

    /** Defaults mirror gradle/libs.versions.toml and serve only TestKit projects, which carry no catalog. */
    fun ktlint(project: Project): String =
        catalog(project)?.findVersion("ktlint")?.orElse(null)?.requiredVersion ?: "1.8.0"

    fun gummyBears(project: Project): String =
        catalog(project)?.findLibrary("gummy-bears-api26")?.orElse(null)?.get()
            ?.let { "${it.module}:${it.versionConstraint.requiredVersion}@signature" }
            ?: "com.toasttab.android:gummy-bears-api-26:0.16.0@signature"
}
