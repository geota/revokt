# Upstream

| Crate | Version | Git commit (`.cargo_vcs_info.json`) | Crate sha256 | Licence |
|---|---|---|---|---|
| `clubcard` | 0.3.4 | `ecca8d1a9e92f9f3b4b910c05fe11c190836501e` | `1f8c5e5335283f9165377506b6b99cdc34fa9634927b201cca7d79fa4d0c8259` | MPL-2.0 (Exhibit A only, no Exhibit B) |
| `clubcard-crlite` | 0.6.2 | `b8ca6961975d51518097dd4eb99d0fdeabee7845` | `345a8de7ab744a39098db70ae604c87dc3e709594c9cf1d6efd164c17305e4bd` | MPL-2.0 (Exhibit A only, no Exhibit B) |

Translation is 1:1 per upstream file into `src/commonMain/kotlin/dev/revokt/clubcard/port/` (spec §3.1). Query and
decoding only: no builder, no encoder, no `Display`, no `ApproximateSizeOf`. Each translated file's header names the
upstream path, crate version and commit.

## Translated files

| Upstream | Translation | Omitted from the file |
|---|---|---|
| `clubcard/src/equation.rs` | `port/Equation.kt` | nothing (`W` is the `WORD_WIDTH` val, fixed at 4) |
| `clubcard/src/query.rs` | `port/Query.kt` | `Filterable` (builder-only); `PartitionMetadata` (always `()` for CRLite) |
| `clubcard/src/clubcard.rs` | `port/Clubcard.kt` | `Display`, `ApproximateSizeOf`, `partition` |
| `clubcard-crlite/src/codec.rs` | `port/Codec.kt` | every `encode`; `impl Codec for ClubcardIndex` moved here from query.rs |
| `clubcard-crlite/src/query.rs` | `port/CrliteQuery.kt` | `to_bytes`, `Display`, `ApproximateSizeOf`, `ClubcardError::Serialize`, the bincode arm of `from_bytes` |
| `clubcard/src/equation.rs` (tests) | `commonTest/…/port/EquationTest.kt` | nothing; the file also holds the #7 equivalence tests and their transcription of upstream `inhomogeneous` (revokt additions, MPL) |
| `clubcard/src/lib.rs`, `clubcard-crlite/src/lib.rs` | none | re-exports only |
| `clubcard/src/builder.rs`, `clubcard-crlite/src/builder.rs` | none | builder (used by `native/revokt-oracle`, never shipped) |

## Deviations, each marked `revokt:` in the source (1–5 decode, 6 allocation, 7 readability)

Spec §6.3 decode strictness and §6.4 storage, applied inside the v4 reader because they cannot be checked after the
fact (duplicates and the `inverted` byte are gone once decoded):

1. `inverted` must be 0 or 1 (C2SP MUST; upstream's v4 reader takes `!= 0`; on v3 this is not a deviation, since
   bincode 1.x rejects any `bool` byte other than 0 or 1).
2. Index block ids strictly increasing (C2SP MUST; also rejects duplicates, which upstream silently overwrites).
3. Coverage log ids distinct (C2SP MUST; upstream overwrites the earlier interval).
4. `approx_filter_rank ≤` column count, checked at decode (upstream indexes out of bounds at query time).
5. Every column gets one zero pad word (spec §6.4); `Equation.eval` is bounds-checked exactly as upstream, so the
   pad changes no result.

Deviations proposed in #7, separately from the port, so the fidelity trade can be judged on its own:

6. **Allocation.** `Equation.add`'s alignment half is the private `align()`, and `Equation.owning(s, a, b)` aligns a
   caller-owned array without the defensive copy and without upstream's throwaway `add(&Equation::zero())`;
   `Equation.inhomogeneous` delegates to it after copying, and `CrliteQuery.asQuery`, whose array is fresh, calls it
   directly. The public `homogeneous`/`inhomogeneous` keep upstream's copy semantics. `EquationTest` checks
   `inhomogeneous`, `owning` and `asQuery` against a literal transcription of upstream's path. Measured with
   thread-allocated bytes over 200,000 `CrliteClubcard.contains` calls after warm-up on JDK 21, one covered SCT,
   4,096 synthetic serials over the enrolled issuers: 357 → 169 B/query on `synthetic.v4.filter` and 250 → 110 B on
   the real `20261017-1-compat.filter`; the PR's independent review measured 301 → 152 and 121 → 63 with corpus
   goldens as keys. On `asQuery`'s path `a[0] |= 1` makes `align()` a no-op; the saving is the copy and `zero()`.
7. **Readability, no allocation saving.** `TimestampInterval.contains` holds upstream's inline
   `low <= ts && ts <= high` from `in_universe`, so the check reads `timestamp in interval` (unsigned and inclusive).
   Upstream's inline form allocates nothing either; this is a Kotlin-idiom change with a fidelity cost, kept as a
   separate item so it can be dropped on its own.

A re-sync that touches `Equation::add`, `Equation::inhomogeneous`, `as_query` (clubcard-crlite `query.rs`) or
`in_universe` re-applies these by hand.

Type mapping: `usize` → `Long` (`m`, offsets, `s`), `approx_filter_rank` → `Int`, `Vec<u8>`/`[u8; 32]` → `okio.ByteString`,
`BTreeMap`/`HashMap` → `Map`, `(LogId, Timestamp)` → `LogTimestamp`, `Option<…>` → nullable, `Result<…, ClubcardError>` →
a thrown `ClubcardError`. SHA-256 comes from Okio (`sha2` upstream).

The v3 (bincode 1.x) reader is not a translation: upstream derives it through serde. It is original Apache-2.0 code in
`dev.revokt.clubcard.api.BincodeV3`, written from the struct layout, with the same strictness rules plus "every `usize`
fits the v4 range".

## Re-syncing

The weekly drift job opens an issue when either crate publishes a new version. A re-sync translates the upstream diff
file by file (`git diff <old-commit> <new-commit> -- src/`), never rewrites, updates this table and the headers, and
re-records the corpus goldens with the new `revokt-oracle` build (docs/dev/corpus.md).
