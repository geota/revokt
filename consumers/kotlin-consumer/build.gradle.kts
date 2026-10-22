// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

val revoktVersion: String = providers.gradleProperty("revokt.version").getOrElse("0.1.0-SNAPSHOT")

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(platform("dev.revokt:revokt-bom:$revoktVersion"))
    implementation("dev.revokt:revokt-engine")
}

application {
    mainClass.set("dev.revokt.consumer.KotlinConsumerKt")
}
