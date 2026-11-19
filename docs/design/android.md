<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Android (`AndroidPlatformTrust`)

Not normative. Moved out of the spec's §5.2 at revision 59 (#216), as it stood at revision 58; milestone: 0.3. A note is promoted into the spec when its milestone starts, and edited there.

- Default delegate: the NSC `RootTrustManager`. `requiresExtendedDelegate()` is false. `pathBuilder`
  is the platform PKIX `CertPathBuilder`. `PlatformTrust.canonicalSubject` defaults to `X500Principal.getName(CANONICAL)`.
- Verified chain: `X509TrustManagerExtensions(delegate).checkServerTrusted(chain, authType, host')`
  at decision step 4; its last element is the anchor. **Known gap, confirmed in Conscrypt:**
  `checkCT` runs only when `host != null && isCTVerificationRequired(host)`, with TLS SCT data
  `null` in the hostname-only variant; under Android 16 CT enforcement a chain that passed step 1 via
  TLS-extension SCTs can throw here and the flow continues with `reconstruct`.
- **Named M1 residual.** On the plain-delegate binding (`X509TrustManagerExtensions` cannot wrap
  it, so step 4 is unavailable), and on any path where the null-host extension call is unavailable,
  the walker cannot complete a chain whose intermediate is omitted (Conscrypt's intermediate index
  accepts such chains, and a revoked leaf without embedded SCTs that delivers SCTs in the TLS
  extension reaches the CT gap on demand) or whose presented intermediate is signed by a retired
  root while Conscrypt completes through a cached cross-certificate; those yield
  `NO_ISSUER(PLATFORM_ONLY)` until M2's preload. Decision step 4's null-host retry closes the CT-gap
  and host-null cases only for an app whose NSC has no `<domain-config>` (`RootTrustManager`
  rejects a null hostname otherwise, Appendix A); any app with a `<domain-config>` ends the CT-gap
  path in `reconstruct` against the default config's anchors (`RootTrustManager.getAcceptedIssuers()`
  returns those only), and a host whose `<domain-config>` declares its own `<trust-anchors>` then
  yields `NO_ISSUER(PLATFORM_ONLY)`; the 0.3 emulator probe runs with and without a `<domain-config>`.
- `RevoktTrustManager` is a public, final, non-anonymous class in `revokt-jsse` with public
  `checkServerTrusted(X509Certificate[], String, String): List<X509Certificate>` and
  `isSameTrustConfiguration(String, String)` declared on it for every platform (`X509TrustManagerExtensions`
  duck-types them; on the JVM the former returns the presented chain); consumer R8 rules keep both; `authType` is not validated.
  AOSP main also carries a 5-arg `checkServerTrusted(chain, ocspData, tlsSctData, authType, host)` on
  `RootTrustManager` and `X509TrustManagerExtensions` (public API level unverified), which would close the
  CT gap if the TLS SCT bytes were available, which app code cannot read from a platform Conscrypt session;
  the 0.3 matrix probes for it.
- `RootTrustManager`'s 2-arg `checkServerTrusted` throws with any `<domain-config>` (§5.4 CIO caveat).
- The 3-arg overload on a plain delegate returns the presented chain after step 1; otherwise the extension call with host', or on a memo hit its null-host retry, is both its return value and its step-4 result (flow step 1).
- Lifecycle observer in its own class, guarded on `androidx.lifecycle.ProcessLifecycleOwner`, installed by `RevoktWork.install` when the dependency resolves, or directly by `RevoktAndroid.observeLifecycle(provider)` for consumers without WorkManager: it calls `sync()` on the process's `onStart` (a `CREATED` instance is started first under the worker's rule, §3, a `start()` throw logged at `WARN` and the sync skipped; queues behind the start task and honours `backoffUntilMillis`, §5.1, so overlap with the worker is harmless); consumer rules carry `-dontwarn androidx.lifecycle.**` and the keep rules verbatim, and keep `AndroidPlatformTrust` (revokt-jsse auto-detects it by name).
