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
}
