# dev.revokt.clubcard.port

The MPL-2.0 package: 1:1 translations of Mozilla's `clubcard` and `clubcard-crlite` crates (spec §3.1), one Kotlin file
per upstream file, each header naming the upstream path, crate version and commit (`UPSTREAM.md` has the table, the
omissions and the five marked deviations). Everything in this directory is MPL-2.0 (REUSE.toml); nothing outside it
may be. No `inline fun`, no `const val`, public only under `@RevoktInternalApi`.

| File | From |
|---|---|
| `Equation.kt` | `clubcard/src/equation.rs` |
| `Query.kt` | `clubcard/src/query.rs` |
| `Clubcard.kt` | `clubcard/src/clubcard.rs` |
| `Codec.kt` | `clubcard-crlite/src/codec.rs` (v4 reader) |
| `CrliteQuery.kt` | `clubcard-crlite/src/query.rs` |

The entry point for the rest of revokt is the Apache-licensed `dev.revokt.clubcard.api.ClubcardFilters.decode`, which
also owns the v3 (bincode) reader.
