// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
plugins {
    application
}

val revoktVersion: String = providers.gradleProperty("revokt.version").getOrElse("0.1.0-SNAPSHOT")

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(platform("dev.revokt:revokt-bom:$revoktVersion"))
    implementation("dev.revokt:revokt-engine-jvm")
}

application {
    mainClass.set("dev.revokt.consumer.JavaConsumer")
}
