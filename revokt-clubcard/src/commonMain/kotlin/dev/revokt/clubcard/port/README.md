# dev.revokt.clubcard.port

The MPL-2.0 package: 1:1 translations of Mozilla's `clubcard` and `clubcard-crlite` crates (spec §3.1), one Kotlin file
per upstream file, each header naming the upstream path, crate version and commit (`UPSTREAM.md`). Everything in this
directory is MPL-2.0 (REUSE.toml); nothing outside it may be. No `inline fun`, no `const val`, public only under
`@RevoktInternalApi`. The translations land with the 0.1 "clubcard port" issue.
