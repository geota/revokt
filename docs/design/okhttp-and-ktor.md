<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OkHttp and Ktor

Not normative. Moved out of the spec's §5.1 and §5.4 at revision 59 (#216), as it stood at revision 58; milestone: 0.3. A note is promoted into the spec when its milestone starts, and edited there.

**HTTP/2 coalescing (OkHttp, verified in `RealConnection.isEligible`).** A request to host B reuses an established HTTP/2 connection to host A when the route's socket address matches, A's certificate covers B and B's pins pass; `checkServerTrusted` never runs for B. revokt therefore evaluates once per connection for the host OkHttp handshook for: the verdict cache key, `RevoktEvent.host`, `hostIn`/`hostSuffixIn`, `OBSERVE` attribution by host and the NSC `<domain-config>` selection at step 1 are all A's, and a coalesced B inherits A's verdict. A consumer that needs per-host policy on coalescable hosts uses a separate `OkHttpClient` or `ConnectionPool` per host (OkHttp treats a non-default `HostnameVerifier` instance as non-coalescable, but revokt does not rely on that). Ktor-OkHttp inherits this; `java.net.http` does not coalesce across hosts (unverified).

- **CIO**: a JVM artifact that also runs on Android, TLS 1.2 only, 2-arg `checkServerTrusted`, never runs CT; **refused on Android by revokt** (`RootTrustManager`'s 2-arg overload throws with any `<domain-config>`).
- **OkHttp**, **Java**, **Android** engines pass the socket or host; every adapter takes an optional
  explicit delegate and replaces a previously configured factory or context.
