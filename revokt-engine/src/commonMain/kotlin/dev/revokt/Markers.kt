// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Cross-artifact plumbing that is public for revokt's own modules only (spec §3.1 item 4). Error-level opt-in;
 * excluded from the API dump and from the 1.0 compatibility promise.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "Internal to revokt: no compatibility promise. Opt in only inside revokt's own modules.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.TYPEALIAS,
)
public annotation class RevoktInternalApi

/**
 * Builders for output types and other testing hooks (spec §4). Warning-level opt-in; outside the 1.0 promise and
 * excluded from the API dump.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.WARNING,
    message = "Testing API: outside the compatibility promise; intended for tests and fakes.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
)
public annotation class RevoktTestingApi
