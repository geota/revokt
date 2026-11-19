<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Approach 1 vs approach 2 for crema

Not normative. Moved out of the spec's §12 at revision 59 (#216), as it stood at revision 58; milestone: background. A note is promoted into the spec when its milestone starts, and edited there.

| | Approach 1 (embed upki via FFI) | Approach 2 (revokt) |
|---|---|---|
| CRLite engine | upstream `upki` (Rust) | our port, two oracles end to end, plus upki as a CI-only second engine |
| What the FFI provides | three functions; config file; no fetch; no Android prebuilt | n/a |
| Still written in Kotlin either way | trust managers, walker, signed fetch, canonical JSON, seeds, policy, Android lifecycle, OneCRL, CRLSet, M3–M5 | same |
| APK impact | ~+320 KB `.so` per ABI, 16 KB page alignment, cargo-ndk matrix | ~+100–150 KB dex; plus the bundled seed in both approaches (1.6 MB `compat`, 6 MB `default`, incompressible) |
| Per-check cost | opens files per check | in-memory columns |
| Failure mode | native crash takes the process | Kotlin exception |

Recommendation: ship **Phase 0 in crema now**; build revokt with the Kotlin engine, which stays
published regardless. **Publication trigger** for `revokt-engine-upki`: if upki's library API
(`RevocationCheckInput::new`, `Store::check`) is stable, the `upki` crate builds for Android targets
under cargo-ndk, and upki gains verify-time CT or MTC evaluation before M3 starts, publish
`revokt-engine-upki` with `revokt-upki-shim` as a separately licensed artifact and re-evaluate a
separate CT/MTC evaluator seam backed by upki for M3 onward; `RevocationEngine` stays CRLite-only (the query ABI is ours, so upki's C ABI is no longer a condition).
