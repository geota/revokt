<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Design notes

Not normative. Each note holds spec text for a later milestone or a cut feature, as it stood when it left the spec
(revision 58, #216), or a design for a later milestone that the spec does not hold yet. A note is promoted into [the spec](../spec/revokt-spec.md) when its milestone starts, and edited
there; until then a note may be stale, and the spec wins.

| Note | Milestone | From |
|---|---|---|
| [trust-managers.md](trust-managers.md) | 0.3 | §5.1: trust managers per delegate, the caches |
| [readiness-and-store-modes.md](readiness-and-store-modes.md) | 0.3 (readiness); read-only mode and the storage fallback deferred (#229) | §5.1: readiness, read-only mode, the storage fallback |
| [content-addressed-store.md](content-addressed-store.md) | 0.3 | #229: content-addressed blobs, one generation file and the pointer (a design, not moved spec text) |
| [listeners.md](listeners.md) | 0.3 | §5.1: listeners |
| [android.md](android.md) | 0.3 | §5.2 |
| [okhttp-and-ktor.md](okhttp-and-ktor.md) | 0.3 | §5.1 HTTP/2 coalescing, §5.4 |
| [walker-pseudocode.md](walker-pseudocode.md) | 0.2, explanatory | §5.1: the `reconstruct` pseudocode; the code and the §9.1 properties are normative |
| [mirror-and-system-cache.md](mirror-and-system-cache.md) | cut by #218 | §7.3 |
| [fetcher-policy.md](fetcher-policy.md) | cut by #219 | §8 |
| [m2-sources.md](m2-sources.md) | M2 | §7.4, §7.5 |
| [crema-approach.md](crema-approach.md) | background | §12 |
