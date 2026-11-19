<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Intermediate preloading, OneCRL, the bundled denylist and CRLSets

Not normative. Moved out of the spec's §7.4 and §7.5 at revision 59 (#216), as it stood at revision 58; milestone: M2. A note is promoted into the spec when its milestone starts, and edited there.

### 7.4 Mozilla intermediate preloading [M2]
Second candidate set by Mozilla's bytes (candidates the walk continues from; a terminal only of last resort when no anchor is reachable through it, `terminalKind = PRELOAD`, §5.1 invariant); splits `NOT_ENROLLED` (with no `INTERMEDIATES` generation the split does not happen and `NOT_ENROLLED` fires; the upki engine never produces it, class collapse); closes the
§5.2 residual; `Dataset.INTERMEDIATES` with `LAST_VERIFIED_POLL` freshness.

### 7.5 OneCRL, bundled denylist and Chrome CRLSet [M2]
OneCRL applied as Firefox does (all records enforced). Denylist project-attested, availability-only.
CRLSet opt-in with CRX3 verification and `crl-set` parsing per Chromium.
