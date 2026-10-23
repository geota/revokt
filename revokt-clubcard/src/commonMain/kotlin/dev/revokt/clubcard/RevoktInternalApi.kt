// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard

/**
 * The clubcard port is public only under this marker (spec §3.1 item 4): revokt-engine opts in, consumers cannot.
 * It is declared here rather than in revokt-engine because revokt-engine depends on this module; the API-dump
 * validator treats it and `dev.revokt.RevoktInternalApi` alike.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "Internal to revokt: the clubcard port carries no compatibility promise and is MPL-2.0 contained.",
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY, AnnotationTarget.CONSTRUCTOR)
public annotation class RevoktInternalApi
