# revokt-clubcard

The MPL-2.0 port of Mozilla's `clubcard` and `clubcard-crlite` crates (spec §3.1). Rules that differ from the root:

<!-- REUSE-IgnoreStart -->
- Translation files live under `src/*/kotlin/**/port/**` only, carry `SPDX-License-Identifier: MPL-2.0` and the
  upstream provenance line (file, crate, version, commit) in the header; `verifyHeaderLocations` fails otherwise.
<!-- REUSE-IgnoreEnd -->
- Apache-licensed glue lives under `…clubcard.api`. Nothing MPL is supported API.
- No `inline fun`, no `const val` in the port (`ClubcardPortRules`); public only under `@RevoktInternalApi`.
- Never shaded or merged into another artifact. `UPSTREAM.md` records the pinned upstream versions; the weekly
  drift job opens an issue when upstream moves; a re-sync translates the upstream diff, never rewrites.
- The oracle corpus (`revokt-oracle`'s `clubcard-crlite` binding, recorded goldens) is the acceptance test.
