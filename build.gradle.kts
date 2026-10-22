// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

buildscript {
    configurations.classpath { resolutionStrategy.activateDependencyLocking() }
}

plugins {
    id("revokt.root")
}
