<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The fetcher's self-revocation policy

Not normative. Moved out of the spec's §8 at revision 59 (#216), as it stood at revision 58; milestone: cut by #219. A note is promoted into the spec when its milestone starts, and edited there.

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
