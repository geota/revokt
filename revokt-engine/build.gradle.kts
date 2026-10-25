// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("revokt.kmp-library")
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(project(":revokt-clubcard"))
            implementation(libs.okio)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        jvmTest.dependencies {
            implementation(libs.kotlin.test.junit5)
            implementation(project.dependencies.platform(libs.junit.bom))
            implementation(libs.junit.jupiter)
            implementation(libs.jazzer.junit)
            runtimeOnly(libs.junit.platform.launcher)
        }
    }
}

// The D8 replay's recording hooks (native/producer-oracle/record-goldens.sh) pass their output paths through.
tasks.withType<Test>().configureEach {
    for (name in listOf("revokt.writeProducerInputs", "revokt.writeGapBaseline", "revokt.writeOracleInputs")) {
        providers.systemProperty(name).orNull?.let { systemProperty(name, it) }
    }
}
