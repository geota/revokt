// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

/**
 * Marks code that calls JDK 9+ networking API missing from Android (`HttpURLConnection.setAuthenticator`,
 * `Authenticator.getDefault()`), which the animal-sniffer API-26 check (CONTRIBUTING §3) then skips. Only the JDK
 * fetcher carries it: spec §4 never uses `JdkHttpFetcher` on Android, where `AndroidHttpFetcher` or the OkHttp fetcher
 * is the default.
 */
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
internal annotation class JdkOnly
