// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// The JVM facade (spec §3 module table): `Revokt` and the types around it arrive with their issues (#139 and on).
// ADR-0003 keeps it a separate artifact.
plugins {
    id("revokt.jvm-library")
}

dependencies {
    // Spec §3 "Dependency scopes": revokt-engine is api here, its types cross the builder signatures
    // (verifyDependencyScopes asserts it).
    api(project(":revokt-engine"))

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // The second TLS provider of the resumed-session SAN test (#290 review).
    testImplementation(libs.conscrypt.openjdk.uber)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// Conscrypt loads its JNI library; JDK 24+ warn and a later release blocks it without this (JDK 17+), as in revokt-engine.
tasks.withType<Test>().configureEach { jvmArgs("--enable-native-access=ALL-UNNAMED") }

animalsniffer {
    // The API-26 check skips only code marked @JdkOnly: JdkHttpFetcher's JDK 9+ calls (setAuthenticator,
    // Authenticator.getDefault), which spec §4 never runs on Android.
    annotation = "dev.revokt.jsse.fetch.JdkOnly"
}
