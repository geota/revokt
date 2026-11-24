<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# C2SP manifest mirrors and the system cache

Not normative. Moved out of the spec's §7.3 at revision 59 (#216), as it stood at revision 58; milestone: cut by #218. A note is promoted into the spec when its milestone starts, and edited there.

Protocol as `upki fetch` (v1.0.1; revision 56, the maintainer's decision Q13, Appendix A). **The manifest**:
`GET <base>manifest.json`; a JSON object with `generated_at` (seconds, an unsigned integer), `comment` (a string,
required) and `files` (alias `filters`), an array of `{filename, size, hash}` with `hash` the hex SHA-256 of the
file. upki sends `If-Modified-Since` from its cached file's modification time and reuses the cache on a 304; revokt
does the same (the maintainer's decision): on the manifest request only, as an IMF-fixdate (RFC 9110 §5.6.7), its
`If-Modified-Since` is the time the live `MIRROR` generation's manifest was stored, taken from the local clock as upki's file time is and persisted in that generation's `meta.json`, none without a live `MIRROR` generation, and a 304 is
`UNCHANGED`. Each file is fetched as `<base><filename>`. Every request has the `FETCH_TIMEOUT` (30 s, upki's too).
**Stages** (revision 58, the maintainer's decision for #194, 2026-11-15): the manifest fetch, a malformed manifest
and an over-cap manifest are stage `CHANGESET`; a file fetch, or a file body whose size or SHA-256 differs from its
manifest entry, is stage `ATTACHMENT`. upki splits its errors the same way, but only by the URL its fetch error
carries (Appendix A). A manifest name or `hash` that fails the rules below is `INDEX_INCONSISTENT` at stage `INDEX`,
as before.
**Redirects** (revision 56, the maintainer's decision; the grammar and the rules below revision 58, the decisions on
#192; code `RedirectingFetcher`, #204): followed in the fetch layer by one shared internal `RedirectingFetcher` that
wraps a C2SP mirror source's `HttpFetcher`; neither the loader nor any client follows one, and the underlying client
never does (§3). Every hop is a new request through the wrapped fetcher, so it goes through the source's TLS (`FetcherTls` until #219 cut it)
and the §8 host checks. **The hop grammar** (revision 58, the maintainer's decisions Q2 and Q3): every URL of the
chain, the request's own included, is read by the one strict grammar the x5u URL is read by too (§7.1), with IP
literals allowed: `https://` in lowercase, so `HTTPS://` is refused; an authority with no userinfo; a host that is a
DNS host name (labels of ASCII letters, digits and `-` of 1 to 63 characters that start and end with a letter or
digit, at most 253, no trailing dot, a last label that starts with a letter; #322), an IPv4 dotted quad with no leading zeros, or a bracketed IPv6 address with no zone
identifier and no `IPvFuture`, a dotted quad standing only for its last 32 bits (so `[1.2.3.4::]` is refused), never a
percent-encoded or non-ASCII host; an optional port of 1 to 65535, and no other port rule; then a path and an optional
query of RFC 3986 `pchar`s, `/` and `?`, every `%` followed by two hex digits; and any fragment, which must be one RFC
3986 allows and is dropped. Anything else is `FAILED`, never repaired. A relative `Location` resolves against the URL
of the request it answered (RFC 3986 §5.2, dot segments removed). **Each hop, the first included, is fetched as revokt
re-serialises it**, never as the configured string or the `Location` value: `https://`, the host lowercased, the port
only when it is not 443, the path (`/` when empty, dot segments removed) and the query as written. Only a 301, 302,
303, 307 or 308 answering a `GET` is followed (every mirror request is one); any other status, another 3xx included,
is returned as the final response, and so is one of the five with no `Location` (the lead's Q1), as reqwest and
Firefox's Necko return it (Appendix A). The mirror client fails any 3xx it is handed but the manifest's 304 above (a
300 or 305, a 302 with no `Location`, or a 304 to a filter request, for example) as `FAILED` with that `httpStatus`
(#194; a reading the lead accepted, from #204's review). A `Location` value is
trimmed of SP and HTAB; distinct values on a redirect response are `FAILED`, as Necko refuses a differing duplicate
`Location`, and equal ones collapse to one (Q4). At most 10 redirects are followed, as reqwest's `Policy::limited(10)`
allows, so a chain makes at most 11 requests; an eleventh redirect is `FAILED`, and so is a hop to a URL already
requested in the chain, the initial URL counted (a loop). **The loop key** (Q5) is the re-serialised URL above, which
has no fragment: scheme and host lowercased and `:443` dropped, the path and the query compared exactly, IPv6
addresses as written, not in a canonical form. It is RFC 3986's simple string comparison (§6.2.1) after that
normalisation, not what every client sends: `%2e` is not a dot segment here, while WHATWG parsers and OkHttp's
`HttpUrl` read `/a/%2e%2e/b` as `/b`, so a loop spelled with `%2e` ends at the hop limit instead; it is `FAILED`
either way, and the host cannot change. `FETCH_TIMEOUT` (30 s) is one deadline for the whole chain, as upki's client
timeout is: each hop is sent with the time left, and a response that arrives at or after the deadline is `FAILED`. A
hop to another host or port than the previous hop's drops the headers that carry credentials (`Authorization`,
`Cookie`, `Cookie2`, `Proxy-Authorization`, `WWW-Authenticate`, compared ignoring case), as reqwest 0.13.0's
`remove_sensitive_headers` does for that hop; unlike reqwest, which rebuilds each hop's headers from the original
request (tower-http 0.6.11 `follow_redirect/mod.rs` line 327) and so re-sends them on a later same-host hop, they stay
dropped on every later hop, whatever its host (revokt sends none today). Every other header, `If-Modified-Since`
included, is sent on every hop unchanged, and no `Referer` is added, a departure from upki: reqwest adds one on every
hop by default and upki does not turn it off (Appendix A).
The body cap (`maxBodyBytes`) and the time left apply to each hop, a 3xx body included, and the caller re-checks the
final response's body (§3). Remote Settings fetches are not wrapped and never follow a redirect (§7.1). **Manifest names** (revision 52; a mirror's data is unsigned, so a name it serves is checked
before it names anything): every `manifest.json` filename passes §6.3's filename rule (1 to 64 bytes of
`[A-Za-z0-9._-]`, not `.` or `..`), does not end in `.` (Win32 strips a trailing `.`, so `meta.json.` would open
`meta.json`), is none of §6.3's reserved names, compared ignoring ASCII case, and is unique in the manifest ignoring
ASCII case. Its name in the generation is §6.5's: the filename itself when it passes
`C2spIndex.isFilename` (C2SP's rule, 1 to 32 bytes of the same characters), otherwise its 32-character derived name,
and the generation's names are unique ignoring ASCII case too. Each file's manifest `hash` is exactly 64 hexadecimal
characters (32 bytes), since it is the one unsigned string that reaches a storage key; its `blobs/<sha256>` key
(§6.5) is the lowercase re-encoding of those 32 bytes. **The base** is the configured `c2spMirror` URL with a `/`
appended when it does not end in one, and the request for `manifest.json` and for every mirror file is the base
followed by its name, nothing else from the manifest entering a URL; a redirect from it follows the rules above (a
`c2spMirror` URL with a query or a fragment throws at `build()`, §4). A manifest with any
failing name or hash is rejected whole before any body is fetched or written: `SyncOutcome.FAILED` with
`INDEX_INCONSISTENT`, stage `INDEX`, as for §6.5's name collision. **The index is built locally** (revision 53, the
maintainer's decision, as `upki fetch` does): a mirror publishes only `manifest.json` and the filter files, and revokt
never fetches an `index.bin` from it. The loader builds the generation's `index.bin` with its own index writer
(§3.2) from each downloaded filter's coverage, under the generation's names, the derived name of a manifest name
over 32 bytes included. **Bootstrap only.** A `MIRROR` or `SYSTEM` generation installs **only when
the dataset has no generation of a higher trust class at all** (no seed, no stored `SIGNED`
generation), its trust class is not below the dataset's `minTrustClass` while
`outcome(UNSIGNED_DATA) == REJECT`, and its coverage passes §6.3; **a `MIRROR` or `SYSTEM` generation with no
filters or no coverage is refused** (revision 56, the maintainer's decision Q24), "no coverage" meaning that every
filter's coverage (its universe) is empty, so `NO_DATA` keeps firing, with the `SOURCE_EMPTY` warning naming the
source (the maintainer's decision): a mirror's sync is `SyncOutcome.FAILED` at stage `INDEX` with `SOURCE_EMPTY` on
`SyncResult.warnings`; a system cache is not installed at `start()` (§6.5's recovery chain moves past it), S
`SOURCE_EMPTY`, and its re-read at a sync installs nothing; it is
evicted by the first
`SIGNED` generation, seed included, and pruned at once. A stale `SIGNED` generation is never
displaced by a lower class: stale-but-signed is the accepted state under the no-ceiling decision,
and a TLS-only mirror must never be able to hide revocations the signed data already holds or turn
into a kill switch. `DataState.trustClass` is the carrier. **Within one sync, sources are attempted
in descending `TrustClass.rank`; a lower-class source is fetched only after every higher-class
source failed in this sync and the bootstrap condition holds** (so a healthy signed install never
downloads the mirror; `MIRROR` precedes `SYSTEM`, which is attempted, not fetched: the cache is re-read). The `c2spCache` is read at `start()` after the
seed, in the recovery order of §6.5. `signedSourceFailing` (3 consecutive failures or more than
`signedSourceFailingAfter` since the last verified changeset, both persisted) is reported in
`RevoktState` and drives nothing else. A configured `c2spCache` counts as local data for the
`NO_DATA` validation rule only when the policy can install it (§4). Residual, recorded in §10: a fresh install without a seed, on-path,
with a mirror certificate the platform trusts can be bootstrapped with attacker data until Mozilla
is reachable; `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA` pushes consumers to ship a seed.
