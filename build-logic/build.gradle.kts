// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// The catalog's Kotlin Gradle plugin, loaded once for both build-logic projects (#275). Without it, kotlin-dsl in
// :convention puts Gradle's embedded 2.4.0 on that project's classpath (GHSA-r937-wjx7-w2jp, fixed in 2.4.20), and
// each project loads its own copy of the plugin.
plugins {
    alias(libs.plugins.kotlin.jvm) apply false
}
