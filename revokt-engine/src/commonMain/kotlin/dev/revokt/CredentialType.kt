// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** The kind of credential evaluated (spec §4). Growable; M5 adds `MTC`, reserved now so it lands additively. */
public enum class CredentialType {
    X509,
}
