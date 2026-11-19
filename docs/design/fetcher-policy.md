<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The fetcher's self-revocation policy

Not normative. Moved out of the spec's §8 at revision 59 (#216), as it stood at revision 58; cut by #219 at revision 61, which moved the rest of its text here (below) and makes every fetch go through the platform's trust manager. A note is promoted into the spec when its milestone starts, and edited there.

- **Fetcher policy**, fixed, **ignores `Enforcement`** (under `OBSERVE` or `OFF` a hit chain on a TLS-only mirror would otherwise be accepted and the signed-source hold could never be set), applies only to the fetcher trust managers, **per source authenticity class, attributed structurally**: each configured source has its own internal trust-manager instance (§5.1 "Anchor snapshot"), created at `build()` and handed to that source's `HttpFetcher` through `FetcherTls`, so a handshake on it is that source's by construction, whatever the peer host and whichever fetcher dropped the host (Ktor CIO needs no exception); **and, as a second condition, an internal instance writes `feedHostBlock`, `updateBlockedBySelf` and `blockedSource` only while a fetch of its source is in flight on it** (the engine knows when it called `fetch`; a handshake outside that window, from a factory that leaked the instance or from a timed-out fetch handshaking late, is rejected on a hit but records nothing); the public `fetcherTrustManager` is a distinct instance over the same snapshot that is always "no fetch in flight": a handshake on it (a consumer that wired the property into another client) is evaluated under this policy but **never writes `feedHostBlock`, `updateBlockedBySelf` or `blockedSource` and never receives the `feedHostRevoked` allowance** (a rejected hit there is just a reject), so unrelated traffic can neither start a hold on the signed source nor inherit its post-hold acceptance; no global pointer exists:
  evidence rules (`REVOKED`; M2: `DENYLIST`, `ONECRL`, `CRLSET`; M4: `DISTRUST`) are evaluated against
  `SIGNED`/`BUNDLED` generations only, so attacker-fed mirror data can never block the signed source;
  every other rule `ALLOW`; no data rules; no exemptions; from M1. For a **TLS-only source**
  (`c2spMirror`) an evidence hit on the host's chain is `REJECT` for as long as its current chain is hit: `SyncOutcome.BLOCKED_BY_SELF` with
  `SyncResult.blockedSource`, `blockedChainSha256` and `blockedLeafSerial` (the name says which rule,
  not the cause: an on-path attacker with a mis-issued-then-revoked certificate produces the same
  signal; compare `blockedChainSha256` with the host's current chain), and `RevoktState.updateBlockedBySelf`.
  For the **end-to-end-signed source** (`remoteSettings` changesets, attachments and x5u, whose payload
  is authenticated by the content signature regardless of transport) the hit is honoured for at most
  `FEED_HOST_HOLD` (24 h, fixed; §5.1 limits) **per source**, measured from the first hit of any of its hosts and persisted in `updater.json` (`feedHostBlock`, cleared only by a hit-free sync that completes after `sinceMillis + FEED_HOST_HOLD`, never by an install alone, so restarts, a CDN alternating or holding two certificates, three hosts in one source, or a record that stays listed for a year cannot extend it: the hold expires once per episode), reported the same way and counting toward `signedSourceFailing`;
  after that the fetch **proceeds** with `RevoktState.feedHostRevoked = true` and the `FEED_HOST_REVOKED`
  warning, so a single signed record naming the feed host (a leaked signing leaf, a producer false
  positive, a seed cut in that window) can never stop the next signed record from arriving: a MITM on
  that path can only serve real signed data, old signed data (rollback guard) or nothing, which a
  packet-dropping attacker already can.

## The rest of the fetcher trust model, as it stood at revision 60

Moved out of the spec's §3, §4, §5.1, §6.5 and the limits table at revision 61 (#219), verbatim. Revision 61's spec
replaces it with one rule: the `HttpFetcher` the consumer supplies handshakes over the platform's TLS and trust
manager, or its own client's, and revokt applies no verdict to its own fetches.

```text
expect class FetcherTls                                     // linuxX64 gate: an empty actual stub, as for canonicalSubject. jvmMain actual: val sslSocketFactory: SSLSocketFactory; val trustManager: X509TrustManager /* that source's internal fetcher trust manager (§5.1 "Anchor snapshot"), never the public fetcherTrustManager */. Hostname verification is binding-owned, never a FetcherTls member (the JDK has no public RFC 6125 verifier): the JDK and Android fetchers rely on HttpsURLConnection's endpoint identification ("HTTPS", set by HttpsClient; a §9 fixture asserts a SAN mismatch is FAILED), the OkHttp fetcher keeps the base client's hostnameVerifier and build() throws IllegalArgumentException when it is not OkHttp's default (a replaced verifier is both a regression and non-coalescable), the Ktor fetchers keep their engine's
```

```text
    fetcherDelegate = corpTrustManager                   // the delegate fetcherTrustManager wraps; default platformTrust.defaultDelegate(); R: where requiresExtendedDelegate() is true a plain X509TrustManager throws IllegalArgumentException from build(), as trustManager(d) does at wiring; R: a RevoktTrustManager as fetcherDelegate throws IllegalArgumentException (the fetch would wait on the data it is supposed to produce); its snapshot is attempted inside start() when a fetching source is configured (§5.1 "Anchor snapshot"); with remoteSettings(MozillaRemoteSettings.DEFAULT) the fetcher contacts firefox.settings.services.mozilla.com, firefox-settings-attachments.cdn.mozilla.net and content-signature-2.cdn.mozilla.net (the NSC and egress allowlist, §7.1)
```

```text
    http = OkHttpFetcher.Factory(baseClient)             // default on the JVM: JdkHttpFetcher.Factory (ProxySelector.getDefault() and a per-connection HttpURLConnection.setAuthenticator that answers RequestorType.PROXY only, JDK 9+, so a trusted intercepting proxy cannot harvest default credentials; a 401/407 is FAILED; revokt configures no proxy; Basic auth to an HTTPS tunnel is disabled by the JDK unless jdk.http.auth.tunneling.disabledSchemes is cleared; proxy-authenticated fleets use OkHttpFetcher.Factory with proxyAuthenticator; setInstanceFollowRedirects(false)). Default on Android (AndroidPlatformTrust): OkHttpFetcher.Factory over a fresh OkHttpClient() when revokt-okhttp resolves (detected by class name), else AndroidHttpFetcher.Factory from revokt-android (HttpURLConnection.setAuthenticator does not exist in Android's libcore, so JdkHttpFetcher is never used there; Android's HttpsURLConnection answers a 407 from the VM-global Authenticator.getDefault() with no per-connection suppression, the §10 residual, which is why the OkHttp fetcher is preferred). OkHttp: sslSocketFactory and x509TrustManager are replaced from FetcherTls unconditionally, the base client's hostnameVerifier is kept (R: must be OkHttp's default), and followRedirects(false), followSslRedirects(false), authenticator(NONE), cookieJar(NO_COOKIES) and cache(null) are forced (a consumer disk cache would serve the first ETag-less request, on a fresh install or after resetState(), from its own max-age) (§7.1 "redirects are never followed" holds at the transport); proxy, dns, interceptors and certificatePinner are inherited and consumer-owned: application and network interceptors see every revokt request, so the consumer must not attach credential-adding interceptors to the base client (the README warns)
```

```text
val revokt.fetcherTrustManager: RevoktTrustManager          // created at build() over fetcherDelegate; snapshot attempted inside start() when a fetching source (remoteSettings) is configured (a failure is S FETCHER_TRUST_UNAVAILABLE, a WARNING: syncs return FAILED until the build succeeds, retried per sync; never a start() throw), else under the factory lock on its first checkServerTrusted in STARTED (§5.1 "Anchor snapshot"); status() reports null snapshot fields until then
```

```text
; val updateBlockedBySelf: Boolean /* a source's own chain is currently rejected on a signed revocation: without a time bound on a TLS-only source (until the host presents a chain that is not hit), for at most FEED_HOST_HOLD on the signed source (§8); cleared when feedHostRevoked takes over */; val feedHostRevoked: Boolean /* the signed source's own chain carries a signed revocation; the hold has expired and fetches proceed loudly (§8); cleared together with feedHostBlock */
```

```text
- S `FETCHER_TRUST_UNAVAILABLE`: `fetcherTrustManager`'s snapshot build failed in `start()` → `WARNING` (cleared by the first successful build); each sync first retries the build on the loader (under the factory lock) and, while it fails, is `FAILED` without a fetch (stage `FETCHER_TRUST`, `sourceId` null, every configured fetching source's `consecutiveFailures` advancing; counting toward `signedSourceFailing` and the failure backoff as any `FAILED`); with a fetching source configured the public instance never attempts the lazy build itself, a handshake on it counts `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` until the loader's retry succeeds.
```

```text
| `FEED_HOST_HOLD` | 24 h | the signed source's `BLOCKED_BY_SELF` hold (§8); fixed, not the policy's `signedSourceFailingAfter` |
```

```text
`fetcherTrustManager` is created at `build()` over `fetcherDelegate`
(default `platformTrust.defaultDelegate()`), as is **one internal instance per configured fetching
source**, handed only to that source's `HttpFetcher.Factory.create(FetcherTls)` as `tls.trustManager`
(typed `X509TrustManager`; a factory that leaks it into another client is outside the contract, and the
in-flight guard of §8 bounds the damage); all of them share one anchor snapshot over `fetcherDelegate`
(one `CandidateIndex`, one id: `refreshAnchors()` on the public instance and the walker-reason trigger
from any internal instance rebuild the one shared reference, and `anchorRefreshFailures` /
`lastAnchorRefreshFailedAtMillis` are reported on the public instance's `status()`) and the fixed fetcher
policy (§8); the internal instances never count toward `maxTrustManagers` and never appear in
`RevoktStatus.trustManagerCount`; the public `fetcherTrustManager` is the consumer-facing instance that
never has a fetch in flight. The shared
snapshot is attempted inside `start()` when a
fetching source (`remoteSettings`) is configured; a failure there is the
`FETCHER_TRUST_UNAVAILABLE` warning, never a `start()` throw (an app that starts revokt in
`Application.onCreate` must not crash-loop where without revokt it would merely fail TLS): each sync
first retries the build on the loader and, while it fails, is `FAILED` **without a fetch** (stage `FETCHER_TRUST`; counting
toward `consecutiveFailures`, `signedSourceFailing` and the failure backoff as any `FAILED`; no
handshake runs on `fetcherTrustManager`, so `unevaluated` does not advance there; the signed source is
never fetched over an unchecked chain). `unevaluated[FETCHER_SNAPSHOT_UNAVAILABLE]` counts only
handshakes a consumer delivers to `fetcherTrustManager` directly while it has no snapshot (the lazy
path below). With no fetching source no `HttpFetcher` and no `FetcherTls` are created, `sync()` never
touches it, and its snapshot is built under the factory lock on the first `checkServerTrusted` it
receives in `STARTED`, after flow step 1; a failed build there is logged at `WARN`, the call returns on the
platform verdict (flow step 1 only, as in `CREATED`), the failure is not memoised and the next call
retries, so goal 3 holds without exception; reading the property or `status()` builds nothing
(`status()` reports null snapshot fields until then). It does not count toward
`maxTrustManagers` (nor do the per-source instances), wraps `fetcherDelegate` (default `platformTrust.defaultDelegate()`), uses the fixed
fetcher policy (§8), never waits, and runs step 2 from M1 against the installed generation.
```
