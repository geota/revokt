// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

import kotlinx.kover.gradle.plugin.dsl.CoverageUnit

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
    // The zlint pin test reads the pin, so a bump that touches only go.mod still re-runs it (no build-cache hit).
    val zlintGoMod = rootProject.file("native/zlint-oracle/go.mod")
    inputs.file(zlintGoMod).withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("revokt.zlintGoMod", zlintGoMod.absolutePath)
}

// Spec §9.2 Acceptance and CONTRIBUTING "Coverage": Kover branch coverage of the parser package of at least 90 % over
// the committed replay (jvmTest), part of `check`. The floor may only be raised.
kover {
    currentProject {
        createVariant("parser") { add("jvm") }
    }
    reports {
        variant("parser") {
            filters { includes { packages("dev.revokt.engine.parse") } }
            verify { rule("parser package branch coverage") { minBound(90, CoverageUnit.BRANCH) } }
        }
    }
}

tasks.named("check") { dependsOn("koverVerifyParser") }
