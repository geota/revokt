// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

pluginManagement {
    includeBuild("build-logic")
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

plugins {
    // Reproducible wrapper + toolchain discipline live in gradle.properties; no settings plugins yet.
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        google()
    }
}

// Library substitution for the detekt rule set that lives in build-logic (dev.revokt.build:revokt-detekt-rules).
includeBuild("build-logic")

rootProject.name = "revokt"

include(":revokt-clubcard")
include(":revokt-engine")
include(":revokt-jsse")
include(":revokt-bom")

// The seed job (spec §6.5, §7.2, #145): publishes the revokt-seed-<channel> data artifacts, never code.
include(":revokt-seed")
project(":revokt-seed").projectDir = file("data/seed")

// CI-only: the upki-backed engine needs JDK 22 and the native shim (native/). Never part of `./gradlew check`.
if (providers.gradleProperty("revokt.native").isPresent) {
    include(":revokt-engine-upki")
}
