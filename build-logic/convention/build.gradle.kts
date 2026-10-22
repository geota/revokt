// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

plugins {
    `kotlin-dsl`
}

group = "dev.revokt.build"

dependencyLocking {
    lockAllConfigurations()
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.detekt.gradle.plugin)
    implementation(libs.ktlint.gradle.plugin)
    implementation(libs.bcv.gradle.plugin)
    implementation(libs.kover.gradle.plugin)
    implementation(libs.animalsniffer.gradle.plugin)

    testImplementation(gradleTestKit())
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlin.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

gradlePlugin {
    plugins {
        register("root") {
            id = "revokt.root"
            implementationClass = "dev.revokt.buildlogic.RootPlugin"
        }
        register("kmpLibrary") {
            id = "revokt.kmp-library"
            implementationClass = "dev.revokt.buildlogic.KmpLibraryPlugin"
        }
        register("jvmLibrary") {
            id = "revokt.jvm-library"
            implementationClass = "dev.revokt.buildlogic.JvmLibraryPlugin"
        }
        register("bom") {
            id = "revokt.bom"
            implementationClass = "dev.revokt.buildlogic.BomPlugin"
        }
    }
}
