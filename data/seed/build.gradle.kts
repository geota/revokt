// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// The seed job (spec §6.5, §7.2; #145): builds the revokt-seed-<channel> data artifacts through the data-artifact
// convention plugin. Nothing compiled here ships; the scheduled run and the GitHub release asset are #149.
plugins {
    id("revokt.data-artifact")
}

dependencies {
    // The job's entry calls the engine's internal core (friendPaths, the plugin) over JdkHttpFetcher.
    implementation(project(":revokt-engine"))
    implementation(project(":revokt-jsse"))
    // The smoke load sees revokt-jsse's public API and the seed jar, nothing else.
    "smokeImplementation"(project(":revokt-jsse"))

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
