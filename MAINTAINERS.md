<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Maintainers

| Handle | Role | Since |
|---|---|---|
| @geota | maintainer, milestone lead (0.1) | 2026-10-22 |

**Phase**: solo-maintainer (ADR-0005). The two-person rule of CONTRIBUTING §5 activates in the PR that adds the second
maintainer; until then: 0 required approvals, an `Independent review` comment on every PR, the full diff read by the
maintainer before auto-merge, `cooling` paused, no release and no 1.0 promise.

**How a maintainer is added or leaves**: GOVERNANCE.md. **Release key custody**: no release key exists yet (none is
created before the second maintainer, CONTRIBUTING §9); this file will carry the fingerprint, the holders and the
rotation record.

**What keeps working untouched for a year** (spec §14): the committed seed and lockfiles build and test offline; the
spec, ADRs and `docs/dev/status.md` describe the state without a maintainer; Renovate PRs wait for a human.
