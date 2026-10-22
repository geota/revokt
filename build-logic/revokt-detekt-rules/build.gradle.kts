// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

plugins {
    alias(libs.plugins.kotlin.jvm)
}

group = "dev.revokt.build"
version = "0.0.0"

dependencyLocking {
    lockAllConfigurations()
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    compileOnly(libs.detekt.api)

    testImplementation(libs.detekt.test)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlin.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
