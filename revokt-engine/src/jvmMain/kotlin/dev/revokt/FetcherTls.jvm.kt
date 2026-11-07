// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * The JVM's [FetcherTls] (spec §3): every handshake of the source's fetcher goes through [sslSocketFactory], whose trust
 * decisions are [trustManager]'s. revokt builds one per fetching source; the constructor is revokt's own.
 */
public actual class FetcherTls
    @RevoktInternalApi
    constructor(
        public val sslSocketFactory: SSLSocketFactory,
        /** The source's trust manager: in 0.2 the configured `fetcherDelegate` (spec §11), never `fetcherTrustManager`. */
        public val trustManager: X509TrustManager,
    )
