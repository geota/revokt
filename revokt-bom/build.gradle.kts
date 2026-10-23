// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("revokt.bom")
}

dependencies {
    constraints {
        // Code artifacts only, including both the KMP root and the -jvm artifact (spec §3). Data artifacts never.
        api(project(":revokt-engine"))
        api("dev.revokt:revokt-engine-jvm:${project.version}")
        api(project(":revokt-clubcard"))
        api("dev.revokt:revokt-clubcard-jvm:${project.version}")
    }
}
