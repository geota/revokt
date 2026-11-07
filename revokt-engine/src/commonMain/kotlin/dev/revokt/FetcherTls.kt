// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The TLS one fetching source's [HttpFetcher] handshakes through (spec §3), handed to [HttpFetcher.Factory.create]. The
 * JVM actual carries an `SSLSocketFactory` and its `X509TrustManager`; hostname verification stays with the fetcher's
 * binding and is never a member here. In 0.2 the trust manager is the configured `fetcherDelegate` itself (spec §11):
 * the per-source fetcher trust managers and the §8 fetcher policy arrive in 0.3.
 */
@Suppress("PublicConstructorOnFinalClass") // the JVM actual's constructor is @RevoktInternalApi; no Builder (spec §3)
public expect class FetcherTls
